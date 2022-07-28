const common = @import("../../common.zig");
const context = @import("context");
const logger = common.log.scoped(.Syscall);
const TODO = common.TODO;

pub const Syscall = common.Syscall;
const root = @import("root");

pub noinline fn handler(argument0: u64, argument1: u64, argument2: u64, argument3: u64, argument4: u64, argument5: u64) callconv(.C) Syscall.RawResult {
    _ = argument5;
    _ = argument4;
    logger.debug("Syscall handler", .{});
    const input = @bitCast(Syscall.Input, argument0);

    {
        const thread = common.arch.get_current_thread();
        for (common.arch.x86_64.interrupts.handlers) |interrupt_handler| {
            const handler_address = @ptrToInt(interrupt_handler);
            common.runtime_assert(@src(), thread.address_space.translate_address(common.VirtualAddress.new(handler_address).aligned_forward(context.page_size)) != null);
        }
    }

    switch (input.options.execution_mode) {
        .blocking => {
            switch (input.options.type) {
                .software => {
                    if (input.id < Syscall.ID.count) {
                        const id = @intToEnum(Syscall.ID, input.id);
                        switch (id) {
                            .thread_exit => {
                                const exit_code = argument1;
                                var maybe_message: ?[]const u8 = null;
                                if (@intToPtr(?[*]const u8, argument2)) |message_ptr| {
                                    const message_len = argument3;
                                    if (message_len != 0) {
                                        const user_message = message_ptr[0..message_len];
                                        logger.debug("User message: {s}", .{user_message});
                                    } else {
                                        logger.err("Message pointer is valid but user didn't specify valid length", .{});
                                    }
                                }
                                thread_exit(exit_code, maybe_message);
                            },
                            .log => {
                                const message_ptr = @intToPtr(?[*]const u8, argument1) orelse @panic("null message ptr");
                                const message_len = argument2;
                                const message = message_ptr[0..message_len];
                                log(message);
                            },
                        }
                    } else {
                        @panic("unrecognized software syscall");
                    }
                },
                .hardware => {
                    if (input.id < Syscall.HardwareID.count) {
                        const id = @intToEnum(Syscall.HardwareID, input.id);
                        return switch (id) {
                            .ask_syscall_manager => ask_syscall_manager(),
                            else => common.panic(@src(), "NI: {s}", .{@tagName(id)}),
                        };
                    } else {
                        @panic("unrecognized hardware syscall");
                    }
                },
            }
        },
        .non_blocking => {
            @panic("non blocking ni");
        },
    }

    return common.zeroes(Syscall.RawResult);
}

/// @HardwareSyscall
pub noinline fn ask_syscall_manager() Syscall.RawResult {
    logger.debug("Asking syscall manager", .{});
    const current_thread = common.arch.get_current_thread();
    const user_syscall_manager = current_thread.syscall_manager.user;
    common.runtime_assert(@src(), user_syscall_manager != null);
    return Syscall.RawResult{
        .a = @ptrToInt(user_syscall_manager),
        .b = 0,
    };
}

/// @HardwareSyscall
pub noinline fn flush_syscall_manager(argument0: u64, argument1: u64, argument2: u64, argument3: u64, argument4: u64, argument5: u64) Syscall.RawResult {
    _ = argument1;
    _ = argument2;
    _ = argument3;
    _ = argument4;
    _ = argument5;
    logger.debug("Asking for a flush in syscall manager", .{});
    const input = @bitCast(Syscall.Input, argument0);
    const hardware_id = @intToEnum(Syscall.HardwareID, input.id);
    common.runtime_assert(@src(), hardware_id == .ask_syscall_manager);
    const current_thread = common.arch.get_current_thread();
    const manager = current_thread.syscall_manager.kernel orelse @panic("wtf");

    logger.debug("Manager completion queue head: {}. Submission: {}", .{ manager.completion_queue.head, manager.submission_queue.head });
    // TODO: improve and bug-free this
    var processed_syscall_count: u64 = 0;
    while (manager.completion_queue.head != manager.submission_queue.head) : ({
        manager.completion_queue.head += @sizeOf(Syscall.Submission);
        processed_syscall_count += 1;
    }) {
        const index = manager.submission_queue.offset + manager.completion_queue.head;
        logger.debug("Index: {}", .{index});
        const submission = @ptrCast(*Syscall.Submission, @alignCast(@alignOf(Syscall.Submission), &manager.buffer[index]));
        const id_arg = submission.arguments[0];
        if (id_arg < Syscall.ID.count) {
            const id = @intToEnum(Syscall.ID, id_arg);
            switch (id) {
                .log => {
                    const message_ptr = @intToPtr(?[*]const u8, submission.arguments[1]) orelse @panic("null message ptr");
                    const message_len = submission.arguments[2];
                    log(message_ptr[0..message_len]);
                },
                else => common.panic(@src(), "NI: {s}", .{@tagName(id)}),
            }
        } else {
            @panic("invalid syscall id");
        }
    }

    logger.debug("Processed syscall count: {}", .{processed_syscall_count});

    // TODO: emit proper result
    return common.zeroes(Syscall.RawResult);
}

pub fn thread_exit(exit_code: u64, maybe_message: ?[]const u8) noreturn {
    logger.debug("We are thread exiting with code: 0x{x}", .{exit_code});
    if (maybe_message) |message| {
        logger.debug("User message: {s}", .{message});
    }

    TODO(@src());
}

pub fn log(message: []const u8) void {
    logger.debug("Log called", .{});
    const current_thread = common.arch.get_current_thread();
    const current_cpu = current_thread.cpu orelse while (true) {};
    const processor_id = current_cpu.id;
    common.arch.Writer.lock.acquire();
    common.arch.writer.print("[ User ] [Core #{}] [Thread #{}] ", .{ processor_id, current_thread.id }) catch unreachable;
    common.arch.writer.writeAll(message) catch unreachable;
    common.arch.writer.writeByte('\n') catch unreachable;
    common.arch.Writer.lock.release();
}

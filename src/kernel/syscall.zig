const std = @import("../common/std.zig");

const arch = @import("arch/common.zig");
const crash = @import("crash.zig");
const kernel = @import("kernel.zig");
const Syscall = @import("../common/syscall.zig");
const TLS = @import("arch/tls.zig");
const user_log = @import("log.zig");
const VirtualAddress = @import("virtual_address.zig");
const VirtualAddressSpace = @import("virtual_address_space.zig");

const logger = std.log.scoped(.Syscall);
const panic = crash.panic;
const TODO = crash.TODO;

pub const KernelManager = struct {
    kernel: ?*Syscall.Manager,
    user: ?*Syscall.Manager,

    pub fn new(virtual_address_space: *VirtualAddressSpace, entry_count: u64) KernelManager {
        std.assert(virtual_address_space.privilege_level == .user);
        const submission_queue_buffer_size = std.align_forward(entry_count * @sizeOf(Syscall.Submission), arch.page_size);
        const completion_queue_buffer_size = std.align_forward(entry_count * @sizeOf(Syscall.Completion), arch.page_size);
        const total_buffer_size = submission_queue_buffer_size + completion_queue_buffer_size;

        const syscall_buffer_physical_address = kernel.physical_address_space.allocate(std.bytes_to_pages(total_buffer_size, arch.page_size, .must_be_exact)) orelse @panic("wtF");
        const kernel_virtual_buffer = syscall_buffer_physical_address.to_higher_half_virtual_address();
        // TODO: stop hardcoding
        const user_virtual_buffer = VirtualAddress.new(0x0000_7f00_0000_0000);
        const submission_physical_address = syscall_buffer_physical_address;
        const completion_physical_address = submission_physical_address.offset(submission_queue_buffer_size);
        virtual_address_space.map(submission_physical_address, kernel_virtual_buffer, .{ .write = false, .user = false });
        virtual_address_space.map(completion_physical_address, kernel_virtual_buffer.offset(submission_queue_buffer_size), .{ .write = true, .user = false });
        virtual_address_space.map(submission_physical_address, user_virtual_buffer, .{ .write = true, .user = true });
        virtual_address_space.map(completion_physical_address, user_virtual_buffer.offset(submission_queue_buffer_size), .{ .write = false, .user = true });

        // TODO: not use a full page
        // TODO: unmap
        // TODO: @Hack undo
        const user_syscall_manager_virtual = virtual_address_space.allocate(std.align_forward(@sizeOf(Syscall.Manager), arch.page_size), null, .{ .write = true, .user = true }) catch @panic("wtff");
        const translated_physical = virtual_address_space.translate_address(user_syscall_manager_virtual) orelse @panic("wtff");
        const kernel_syscall_manager_virtual = translated_physical.to_higher_half_virtual_address();
        const trans_result = virtual_address_space.translate_address(kernel_syscall_manager_virtual) orelse @panic("wtf");
        std.assert(trans_result.value == translated_physical.value);
        const user_syscall_manager = kernel_syscall_manager_virtual.access(*Syscall.Manager);
        user_syscall_manager.* = Syscall.Manager{
            .buffer = user_virtual_buffer.access([*]u8)[0..total_buffer_size],
            .submission_queue = Syscall.QueueDescriptor{
                .head = 0,
                .tail = 0,
                .offset = 0,
            },
            .completion_queue = Syscall.QueueDescriptor{
                .head = 0,
                .tail = 0,
                .offset = @intCast(u32, submission_queue_buffer_size),
            },
        };

        const physical_kernel = virtual_address_space.translate_address(kernel_syscall_manager_virtual) orelse @panic("wtf");
        const physical_user = virtual_address_space.translate_address(user_syscall_manager_virtual) orelse @panic("wtf");
        std.assert(physical_user.value == physical_kernel.value);

        return KernelManager{
            .kernel = kernel_syscall_manager_virtual.access(*Syscall.Manager),
            .user = user_syscall_manager_virtual.access(*Syscall.Manager),
        };
    }
};

pub noinline fn handler(input: Syscall.Input, argument1: u64, argument2: u64, argument3: u64, argument4: u64, argument5: u64) callconv(.C) Syscall.RawResult {
    //{
    //const thread = common.arch.get_current_thread();
    //for (common.arch.x86_64.interrupts.handlers) |interrupt_handler| {
    //const handler_address = @ptrToInt(interrupt_handler);
    //std.assert(thread.address_space.translate_address(common.VirtualAddress.new(handler_address).aligned_forward(context.page_size)) != null);
    //}
    //}

    const submission = Syscall.Submission{
        .input = input,
        .arguments = .{ argument1, argument2, argument3, argument4, argument5 },
    };
    const current_thread = TLS.get_current();

    switch (submission.input.options.execution_mode) {
        .blocking => {
            switch (submission.input.options.type) {
                .software => {
                    if (submission.input.id < Syscall.ServiceID.count) {
                        const id = @intToEnum(Syscall.ServiceID, submission.input.id);
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
                            .read_file => {
                                const filename = blk: {
                                    const ptr = @intToPtr(?[*]const u8, submission.arguments[0]) orelse @panic("null message ptr");
                                    const len = submission.arguments[1];
                                    break :blk ptr[0..len];
                                };

                                const main_storage = kernel.device_manager.devices.filesystem.get_main_device();
                                const file = main_storage.read_file(current_thread.address_space, filename) catch unreachable;
                                std.assert(file.len > 0);
                                logger.debug("File: 0x{x}", .{@ptrToInt(file.ptr)});
                                logger.debug("Len: {}", .{file.len});
                                logger.debug("File[0]: 0x{x}", .{file[0]});

                                const result = Syscall.RawResult{
                                    .a = @ptrToInt(file.ptr),
                                    .b = file.len,
                                };
                                std.assert(result.a != 0);
                                std.assert(result.b != 0);
                                return result;
                            },
                            .allocate_memory => {
                                TODO();
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
                            else => panic("NI: {s}", .{@tagName(id)}),
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

    return std.zeroes(Syscall.RawResult);
}

/// @HardwareSyscall
pub noinline fn ask_syscall_manager() Syscall.RawResult {
    logger.debug("Asking syscall manager", .{});
    const current_thread = TLS.get_current();
    const user_syscall_manager = current_thread.syscall_manager.user;
    std.assert(user_syscall_manager != null);
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
    std.assert(hardware_id == .ask_syscall_manager);
    const current_thread = TLS.get_current();
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
                else => panic("NI: {s}", .{@tagName(id)}),
            }
        } else {
            @panic("invalid syscall id");
        }
    }

    logger.debug("Processed syscall count: {}", .{processed_syscall_count});

    // TODO: emit proper result
    return std.zeroes(Syscall.RawResult);
}

pub fn thread_exit(exit_code: u64, maybe_message: ?[]const u8) noreturn {
    logger.debug("We are thread exiting with code: 0x{x}", .{exit_code});
    if (maybe_message) |message| {
        logger.debug("User message: {s}", .{message});
    }

    TODO();
}

pub fn log(message: []const u8) void {
    const current_thread = TLS.get_current();
    const current_cpu = current_thread.cpu orelse while (true) {};
    const processor_id = current_cpu.id;
    user_log.lock.acquire();
    defer user_log.lock.release();
    user_log.writer.print("[ User ] [Core #{}] [Thread #{}] ", .{ processor_id, current_thread.id }) catch unreachable;
    user_log.writer.writeAll(message) catch unreachable;
    user_log.writer.writeByte('\n') catch unreachable;
}

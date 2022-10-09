const common = @import("common");
const align_forward = common.align_forward;
const assert = common.assert;
const logger = common.log.scoped(.Syscall);
const Service = common.Syscall.Service;
const Submission = common.Syscall.Submission;
const Syscall = common.Syscall.Syscall;
const Manager = common.Syscall.Manager;
const services = common.Syscall.services;
const zeroes = common.zeroes;

const RNU = @import("RNU");
const Message = RNU.Message;
const panic = RNU.panic;
const TODO = RNU.TODO;
const VirtualAddress = RNU.VirtualAddress;
const VirtualAddressSpace = RNU.VirtualAddressSpace;

const kernel = @import("kernel");

const arch = @import("arch");
const TLS = arch.TLS;

pub const KernelManager = struct {
    kernel: ?*Manager,
    user: ?*Manager,

    pub fn new(virtual_address_space: *VirtualAddressSpace, entry_count: u64) KernelManager {
        assert(virtual_address_space.privilege_level == .user);
        const submission_queue_buffer_size = align_forward(entry_count * @sizeOf(Submission), arch.page_size);
        const completion_queue_buffer_size = align_forward(entry_count * @sizeOf(Syscall.Result), arch.page_size);
        const total_buffer_size = submission_queue_buffer_size + completion_queue_buffer_size;

        const syscall_buffer_physical_region = kernel.physical_address_space.allocate_pages(arch.page_size, @divFloor(total_buffer_size, arch.page_size), .{ .zeroed = true }) orelse @panic("wtF");
        // TODO: stop hardcoding
        const user_virtual_buffer = VirtualAddress.new(0x0000_7f00_0000_0000);
        const submission_physical_address = syscall_buffer_physical_region.address;
        const completion_physical_address = submission_physical_address.offset(submission_queue_buffer_size);
        virtual_address_space.map(submission_physical_address, user_virtual_buffer, arch.page_size, .{ .write = true, .user = true }) catch unreachable;
        virtual_address_space.map(completion_physical_address, user_virtual_buffer.offset(submission_queue_buffer_size), arch.page_size, .{ .write = false, .user = true }) catch unreachable;

        // TODO: not use a full page
        // TODO: unmap
        // TODO: @Hack undo
        const user_syscall_manager_virtual = virtual_address_space.allocate(align_forward(@sizeOf(Manager), arch.page_size), null, .{ .write = true, .user = true }) catch @panic("wtff");
        const translated_physical = virtual_address_space.translate_address(user_syscall_manager_virtual) orelse @panic("wtff");
        const kernel_syscall_manager_virtual = translated_physical.to_higher_half_virtual_address();
        const trans_result = virtual_address_space.translate_address(kernel_syscall_manager_virtual) orelse @panic("wtf");
        assert(trans_result.value == translated_physical.value);
        const user_syscall_manager = kernel_syscall_manager_virtual.access(*Manager);
        user_syscall_manager.* = Manager{
            .buffer = user_virtual_buffer.access([*]u8)[0..total_buffer_size],
            .submission_queue = Manager.QueueDescriptor{
                .head = 0,
                .tail = 0,
                .offset = 0,
            },
            .completion_queue = Manager.QueueDescriptor{
                .head = 0,
                .tail = 0,
                .offset = @intCast(u32, submission_queue_buffer_size),
            },
        };

        const physical_kernel = virtual_address_space.translate_address(kernel_syscall_manager_virtual) orelse @panic("wtf");
        const physical_user = virtual_address_space.translate_address(user_syscall_manager_virtual) orelse @panic("wtf");
        assert(physical_user.value == physical_kernel.value);

        return KernelManager{
            .kernel = kernel_syscall_manager_virtual.access(*Manager),
            .user = user_syscall_manager_virtual.access(*Manager),
        };
    }
};

const HandlerPrototype = fn (Submission.Input, u64, u64, u64, u64, u64) callconv(.C) Syscall.Result;
pub const handler: *const HandlerPrototype = kernel_syscall_handler;

pub export fn kernel_syscall_handler(input: Submission.Input, argument1: u64, argument2: u64, argument3: u64, argument4: u64, argument5: u64) callconv(.C) Syscall.Result {
    const submission = Submission{
        .input = input,
        .arguments = [_]u64{ argument1, argument2, argument3, argument4, argument5 },
    };
    const current_thread = TLS.get_current();

    switch (submission.input.options.execution_mode) {
        .blocking => {
            switch (submission.input.options.type) {
                .service => {
                    if (submission.input.id < Service.count) {
                        const id = @intToEnum(Service.ID, submission.input.id);

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
                                const file = main_storage.read_file(current_thread.process.virtual_address_space, filename) catch unreachable;
                                assert(file.len > 0);
                                logger.debug("File: 0x{x}", .{@ptrToInt(file.ptr)});
                                logger.debug("Len: {}", .{file.len});
                                logger.debug("File[0]: 0x{x}", .{file[0]});

                                const result = Syscall.Result{
                                    .a = @ptrToInt(file.ptr),
                                    .b = file.len,
                                };
                                assert(result.a != 0);
                                assert(result.b != 0);
                                return result;
                            },
                            .allocate_memory => {
                                logger.debug("Submission: {}", .{submission});
                                const size = submission.arguments[0];
                                const alignment = submission.arguments[1];
                                const allocation_result = current_thread.process.virtual_address_space.heap.allocator.allocate_bytes(size, alignment) catch unreachable;
                                const result = Syscall.Result{
                                    .a = allocation_result.address,
                                    .b = allocation_result.size,
                                };
                                assert(result.a != 0);
                                assert(result.b != 0);

                                return result;
                            },
                            .get_framebuffer => {
                                @panic("todo get framebuffer syscall");
                                //const framebuffer = current_thread.framebuffer;
                                //return Syscall.RawResult{
                                //.a = @ptrToInt(framebuffer),
                                //.b = 0,
                                //};
                            },
                            .send_message => {
                                const message = Message{
                                    .id = @intToEnum(Message.ID, submission.arguments[0]),
                                    .context = @intToPtr(?*anyopaque, submission.arguments[1]),
                                };
                                logger.debug("Send message: {}", .{message.id});
                                current_thread.message_queue.send(message) catch unreachable;

                                return Syscall.Result{
                                    .a = 0,
                                    .b = 0,
                                };
                            },
                            .receive_message => {
                                const message = current_thread.message_queue.receive_message() catch unreachable;
                                logger.debug("Receive message: {}", .{message});
                                return Syscall.Result{
                                    .a = @enumToInt(message.id),
                                    .b = @ptrToInt(message.context),
                                };
                            },
                            .create_plain_window => {
                                @panic("todo create_plain_window");
                            },
                        }
                    } else {
                        @panic("unrecognized software syscall");
                    }
                },
                .syscall => {
                    if (input.id < Syscall.count) {
                        const id = @intToEnum(Syscall.ID, input.id);
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

    return zeroes(Syscall.Result);
}

/// @HardwareSyscall
pub noinline fn ask_syscall_manager() Syscall.Result {
    logger.debug("Asking syscall manager", .{});
    const current_thread = TLS.get_current();
    const user_syscall_manager = current_thread.syscall_manager.user;
    assert(user_syscall_manager != null);
    return Syscall.Result{
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
    assert(hardware_id == .ask_syscall_manager);
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
                    const message_ptr = @intToPtr(?[*]const u8, submission.arguments[0]) orelse @panic("null message ptr");
                    const message_len = submission.arguments[1];
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
    return zeroes(Syscall.RawResult);
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
    arch.writer_lock.acquire();
    defer arch.writer_lock.release();
    arch.writer.print("[ User ] [Core #{}] [Thread #{}] ", .{ processor_id, current_thread.id }) catch unreachable;
    arch.writer.writeAll(message) catch unreachable;
    arch.writer.writeByte('\n') catch unreachable;
}

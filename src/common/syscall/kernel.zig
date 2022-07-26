const common = @import("../../common.zig");
const log = common.log.scoped(.Syscall);
const TODO = common.TODO;

pub const Syscall = common.Syscall;

pub const RawHandler = fn (argument0: u64, argument1: u64, argument2: u64, argument3: u64, argument4: u64, argument5: u64) callconv(.C) Syscall.RawResult;
pub const Handler = fn (argument0: u64, argument1: u64, argument2: u64, argument3: u64, argument4: u64, argument5: u64) callconv(.C) Syscall.Result;
pub const raw_handlers = [Syscall.HardwareID.count]RawHandler{
    ask_syscall_manager, //common.safe_function_cast(ask_syscall_manager, common.SafeFunctionCastParameters{ .FunctionType = RawHandler }) catch |err| @compileLog(err),
    flush_syscall_manager,
};

pub noinline fn ask_syscall_manager(argument0: u64, argument1: u64, argument2: u64, argument3: u64, argument4: u64, argument5: u64) callconv(.C) Syscall.RawResult {
    _ = argument1;
    _ = argument2;
    _ = argument3;
    _ = argument4;
    _ = argument5;
    log.debug("Asking syscall manager", .{});
    const id = @intToEnum(Syscall.HardwareID, argument0);
    common.runtime_assert(@src(), id == .ask_syscall_manager);
    const current_thread = common.arch.get_current_thread();
    const user_syscall_manager = current_thread.syscall_manager.user;
    common.runtime_assert(@src(), user_syscall_manager != null);
    return Syscall.RawResult{
        .a = @ptrToInt(user_syscall_manager),
        .b = 0,
    };
}

pub noinline fn flush_syscall_manager(argument0: u64, argument1: u64, argument2: u64, argument3: u64, argument4: u64, argument5: u64) callconv(.C) Syscall.RawResult {
    _ = argument1;
    _ = argument2;
    _ = argument3;
    _ = argument4;
    _ = argument5;
    log.debug("Asking for a flush in syscall manager", .{});
    const hardware_id = @intToEnum(Syscall.HardwareID, argument0);
    common.runtime_assert(@src(), hardware_id == .flush_syscall_manager);
    const current_thread = common.arch.get_current_thread();
    const manager = current_thread.syscall_manager.kernel orelse @panic("wtf");

    log.debug("Manager completion queue head: {}. Submission: {}", .{ manager.completion_queue.head, manager.submission_queue.head });
    // TODO: improve and bug-free this
    while (manager.completion_queue.head != manager.submission_queue.head) {
        const submission = @ptrCast(*Syscall.Submission, @alignCast(@alignOf(Syscall.Submission), &manager.buffer[manager.submission_queue.offset + manager.submission_queue.head]));
        const id_arg = submission.arguments[0];
        if (id_arg < Syscall.ID.count) {
            const id = @intToEnum(Syscall.ID, id_arg);
            switch (id) {
                else => common.panic(@src(), "NI: {s}", .{@tagName(id)}),
            }
        } else {
            @panic("invalid syscall id");
        }
    }
    @panic("reached here");
}

//pub fn thread_exit(syscall_id: Syscall.ID, exit_code: u64, maybe_message_ptr: ?[*]const u8, message_len: u64, _: u64, _: u64) callconv(.C) noreturn {
//common.runtime_assert(@src(), syscall_id == .thread_exit);
//log.debug("We are thread exiting with code: 0x{x}", .{exit_code});
//if (maybe_message_ptr) |message_ptr| {
//if (message_len != 0) {
//const user_message = message_ptr[0..message_len];
//log.debug("User message: {s}", .{user_message});
//} else {
//log.err("Message pointer is valid but user didn't specify valid length", .{});
//}
//}

//TODO(@src());
//}

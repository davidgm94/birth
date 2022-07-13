const common = @import("../common.zig");
pub const kernel = @import("syscall/kernel.zig");

const log = common.log.scoped(.Syscall);
const TODO = common.TODO;
const x86_64 = common.arch.x86_64;

pub const ID = enum(u64) {
    thread_exit = 0,
};

pub const count = common.enum_values(ID).len;

const syscall = common.arch.Syscall.user_syscall_entry_point;

pub const ThreadExitParameters = struct {
    message: ?[]const u8 = null,
    exit_code: u64,
};
pub inline fn thread_exit(thread_exit_parameters: ThreadExitParameters) noreturn {
    var message_ptr: ?[*]const u8 = undefined;
    var message_len: u64 = undefined;
    if (thread_exit_parameters.message) |message| {
        message_ptr = message.ptr;
        message_len = message.len;
    } else {
        message_ptr = null;
        message_len = 0;
    }
    _ = syscall(@enumToInt(ID.thread_exit), thread_exit_parameters.exit_code, @ptrToInt(message_ptr), message_len, 0, 0);
    unreachable;
}

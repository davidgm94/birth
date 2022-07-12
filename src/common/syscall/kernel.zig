const common = @import("../../common.zig");
const log = common.log.scoped(.Syscall);

pub const Syscall = common.Syscall;

pub const Handler = fn (argument0: u64, argument1: u64, argument2: u64, argument3: u64, argument4: u64, argument5: u64) callconv(.C) u64;
pub const handlers = [Syscall.count]Handler{
    @ptrCast(Handler, thread_exit),
};

pub fn thread_exit(syscall_id: Syscall.ID, exit_code: u64, _: u64, _: u64, _: u64, _: u64) callconv(.C) noreturn {
    common.runtime_assert(@src(), syscall_id == .thread_exit);
    log.debug("We are thread exiting with code: 0x{x}", .{exit_code});
    unreachable;
}

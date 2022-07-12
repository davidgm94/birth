const common = @import("../common.zig");
pub const kernel = @import("syscall/kernel.zig");

const log = common.log.scoped(.Syscall);
const TODO = common.TODO;
const x86_64 = common.arch.x86_64;

pub const ID = enum(u64) {
    thread_exit = 0,
};

pub const count = common.enum_values(ID).len;

const user_entry_point = common.arch.Syscall.user_entry_point;

pub fn thread_exit(exit_code: u64, _: u64, _: u64, _: u64, _: u64) noreturn {
    _ = user_entry_point(@enumToInt(ID.thread_exit), exit_code, 0, 0, 0, 0);
    unreachable;
}

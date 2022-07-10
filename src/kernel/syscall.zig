const kernel = @import("root");
const common = @import("../common.zig");

const log = common.log.scoped(.Syscall);
const TODO = common.TODO;
const x86_64 = common.arch.x86_64;

pub const ID = enum(u64) {
    thread_exit = 0,
};

const Handler = fn (argument0: u64, argument1: u64, argument2: u64, argument3: u64, argument4: u64, argument5: u64) callconv(.C) u64;
pub const syscall_handlers = [1]Handler{
    thread_exit,
};

pub export fn syscall_handler(argument0: u64, argument1: u64, argument2: u64, argument3: u64, argument4: u64, argument5: u64) callconv(.C) u64 {
    const id = @intToEnum(ID, argument0);
    log.debug("Syscall #{}: {s}", .{ argument0, @tagName(id) });
    return syscall_handlers[argument0](argument0, argument1, argument2, argument3, argument4, argument5);
}

pub fn thread_exit(argument0: u64, argument1: u64, argument2: u64, argument3: u64, argument4: u64, argument5: u64) callconv(.C) u64 {
    log.debug("Argument: {}", .{argument0});
    log.debug("Argument: {}", .{argument1});
    log.debug("Argument: {}", .{argument2});
    log.debug("Argument: {}", .{argument3});
    log.debug("Argument: {}", .{argument4});
    log.debug("Argument: {}", .{argument5});
    log.debug("Argument: {}", .{argument0});
    return 123;
}

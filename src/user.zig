const lib = @import("lib");
const assert = lib.assert;
const ExecutionMode = lib.Syscall.ExecutionMode;

const rise = @import("rise");
const capabilities = rise.capabilities;
pub const Syscall = rise.capabilities.Syscall;

pub const arch = @import("user/arch.zig");
pub const thread = @import("user/thread.zig");

comptime {
    @export(arch._start, .{ .linkage = .Strong, .name = "_start" });
}

pub const Scheduler = extern struct {
    time_slice: u32,
    core_id: u32,
};

pub fn zigPanic(message: []const u8, _: ?*lib.StackTrace, _: ?usize) noreturn {
    @call(.always_inline, panic, .{ "{s}", .{message} });
}

pub fn panic(comptime format: []const u8, arguments: anytype) noreturn {
    lib.log.scoped(.PANIC).err(format, arguments);
    while (true) {
        asm volatile ("pause" ::: "memory");
    }
}

pub inline fn currentScheduler() *Scheduler {
    return arch.currentScheduler();
}

fn schedulerInitDisabled(scheduler: *arch.Scheduler) void {
    assert(scheduler.common.generic.disabled);
    // Architecture-specific initialization
    scheduler.initDisabled();
    scheduler.generic.time_slice = 1;
    // TODO: capabilities
}

pub var is_init = false;

export fn riseInitializeDisabled(scheduler: *arch.Scheduler, arg_init: bool) callconv(.C) noreturn {
    // TODO: delete when this code is unnecessary. In the meanwhile it counts as a sanity check
    assert(arg_init);
    is_init = arg_init;
    schedulerInitDisabled(scheduler);
    thread.initDisabled(scheduler);
}

pub const VirtualAddress = enum(usize) {
    _,

    pub inline fn new(address: anytype) VirtualAddress {
        const T = @TypeOf(address);
        return switch (T) {
            usize => @intToEnum(VirtualAddress, address),
            else => switch (@typeInfo(T)) {
                .Fn => @intToEnum(VirtualAddress, @ptrToInt(&address)),
                .Pointer => @intToEnum(VirtualAddress, @ptrToInt(address)),
                else => {
                    @compileLog(T);
                    @compileError("HA!");
                },
            },
        };
    }

    pub inline fn value(va: VirtualAddress) usize {
        return @enumToInt(va);
    }

    pub inline fn sub(va: *VirtualAddress, substraction: usize) void {
        @ptrCast(*usize, va).* -= substraction;
    }
};

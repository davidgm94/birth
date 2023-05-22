comptime {
    if (lib.os != .freestanding) @compileError("This file is not meant to be imported in build.zig");
}

const lib = @import("lib");
const assert = lib.assert;
const ExecutionMode = lib.Syscall.ExecutionMode;

const rise = @import("rise");
const capabilities = rise.capabilities;

pub const arch = @import("user/arch.zig");
pub const thread = @import("user/thread.zig");

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

pub fn syscall(comptime capability_type: capabilities.Type, comptime capability_command: @field(capabilities, @tagName(capability_type)), arguments: capabilities.Arguments(capability_type, capability_command)) capabilities.ErrorSet(capability_type, capability_command).Error!capabilities.Result(capability_type, capability_command) {
    const options = rise.syscall.Options{
        .rise = .{
            .type = capability_type,
            .command = @enumToInt(capability_command),
        },
    };

    const raw_arguments: [6]usize = switch (@typeInfo(@TypeOf(arguments))) {
        .Pointer => |pointer| switch (pointer.size) {
            .Slice => .{0} ** 4 ++ [2]usize{ @ptrToInt(arguments.ptr), arguments.len },
            else => @compileError("Unexpected pointer type"),
        },
        .Void => .{0} ** 6,
        else => |_| @compileError("t: " ++ @typeName(@TypeOf(arguments))),
    };

    const result = arch.syscall(options, raw_arguments);
    const ThisErrorSet = capabilities.ErrorSet(capability_type, capability_command);
    const error_enum = @intToEnum(ThisErrorSet.Enum, result.rise.first.@"error");
    return switch (error_enum) {
        .ok => switch (capabilities.Result(capability_type, capability_command)) {
            noreturn => unreachable,
            else => while (true) {},
        },
        inline else => |comptime_error_enum| @field(ThisErrorSet.Error, @tagName(comptime_error_enum)),
    };
}

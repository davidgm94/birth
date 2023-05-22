const lib = @import("lib");
const assert = lib.assert;

const rise = @import("rise");
const capabilities = rise.capabilities;
const syscall = rise.syscall;

const user = @import("user");

pub const rawSyscall = user.arch.syscall;

pub fn shutdown() noreturn {
    _ = invoke(.cpu, .shutdown, {});
    unreachable;
}

pub fn log(message: []const u8) void {
    _ = invoke(.io, .log, [2]usize{ @ptrToInt(message.ptr), message.len });
}

pub fn getCoreId() !u32 {
    const result = invoke(.cpu, .get_core_id, {});
    const core_id = @truncate(u32, result.rise.second);
    return core_id;
}

pub fn allocate(size: usize) !*anyopaque {
    _ = size;
    @panic("TODO allocate");
}

pub inline fn invoke(comptime capability_type: capabilities.Type, comptime capability_command: @field(capabilities, @tagName(capability_type)), arguments: anytype) syscall.Result {
    const options = syscall.Options{
        .rise = .{
            .type = capability_type,
            .command = @enumToInt(capability_command),
        },
    };
    const raw_arguments = switch (@TypeOf(arguments)) {
        void => .{0} ** rise.syscall.argument_count,
        [2]usize => arguments ++ .{0} ** 4,
        else => @compileError("Type not supported"),
    };
    return rawSyscall(options, raw_arguments);
}

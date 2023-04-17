const lib = @import("lib");
const assert = lib.assert;

const rise = @import("rise");
const capabilities = rise.capabilities;
const syscall = rise.syscall;

const user = @import("user");

pub const rawSyscall = user.arch.syscall;

pub fn shutdown() noreturn {
    _ = invoke(.cpu, .shutdown, 0, {});
    unreachable;
}

pub fn log(message: []const u8) void {
    _ = invoke(.io, .stdout, 0, [2]usize{ @ptrToInt(message.ptr), message.len });
}

pub fn getCoreId() u32 {
    const result = invoke(.cpu, .get_core_id, 0, {});
    const core_id = @truncate(u32, result.rise.second);
    return core_id;
}

pub inline fn invoke(comptime capability_type: capabilities.Type, comptime capability_command: capabilities.Command.Generic(capability_type), address: u32, arguments: anytype) syscall.Result {
    const options = syscall.Options{
        .rise = .{
            .type = capability_type,
            .command = @enumToInt(capability_command),
            .address = address,
        },
    };
    const raw_arguments = switch (@TypeOf(arguments)) {
        void => .{0} ** rise.syscall.argument_count,
        [2]usize => arguments ++ .{0} ** 4,
        else => @compileError("Type not supported"),
    };
    return rawSyscall(options, raw_arguments);
}

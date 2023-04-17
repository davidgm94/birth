const lib = @import("lib");
const assert = lib.assert;

const rise = @import("rise");
const capabilities = rise.capabilities;
const syscall = rise.syscall;

const user = @import("user");

pub const rawSyscall = user.arch.syscall;

pub inline fn invoke(comptime capability_type: capabilities.Type, comptime capability_command: capabilities.Command.Generic(capability_type), address: u32, arguments: capabilities.Arguments(capability_type, capability_command)) syscall.Result {
    const options = syscall.Options{
        .rise = .{
            .type = capability_type,
            .command = @enumToInt(capability_command),
            .address = address,
        },
    };
    const raw_arguments = switch (@TypeOf(arguments)) {
        void => .{0} ** rise.syscall.argument_count,
        else => @compileError("Type not supported"),
    };
    return rawSyscall(options, raw_arguments);
}

pub fn shutdown() noreturn {
    _ = invoke(.cpu, .shutdown, 0, {});
    unreachable;
}

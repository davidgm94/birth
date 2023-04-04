const lib = @import("lib");
const assert = lib.assert;
const Capabilities = lib.Capabilities;
const Capability = Capabilities.Capability;
const Syscall = lib.Syscall;

const user = @import("user");

pub const rawSyscall = user.arch.x86_64.syscall;

pub fn getCoreId() !u8 {
    const result = invoke(lib.Capabilities.Capability.kernel, @enumToInt(lib.Capabilities.Command.Kernel.get_core_id), .{ 0, 0, 0, 0, 0, 0 });
    unwrap(result) catch {
        @panic("Syscall failed");
    };

    return @intCast(u8, result.second);
}

pub fn logMessage(message: []const u8) !void {
    const result = invoke(lib.Capabilities.Capability.io, @enumToInt(lib.Capabilities.Command.IO.log_message), .{ @ptrToInt(message.ptr), message.len, 0, 0, 0, 0 });
    unwrap(result) catch {
        @panic("Syscall failed");
    };
}

pub const UnwrapError = error{
    failed,
};

fn unwrap(result: lib.Syscall.Result.Rise) !void {
    assert(result.first.convention == .rise);

    return switch (result.first.@"error") {
        0 => {},
        else => UnwrapError.failed,
    };
}

pub fn invoke(capability: Capability.Reference, capability_invocation_type: u16, arguments: [6]usize) lib.Syscall.Result.Rise {
    const cptr = capability.getAddress();
    const slot = capability.getLevel();
    const options = Syscall.Options{
        .rise = .{
            .address = cptr,
            .slot = slot,
            .invocation = capability_invocation_type,
            .convention = .rise,
        },
    };

    const result = rawSyscall(options, arguments);
    return result.rise;
}

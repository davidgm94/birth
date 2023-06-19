const lib = @import("lib");
const log = lib.log;
const assert = lib.assert;
const ExecutionMode = lib.Syscall.ExecutionMode;

const rise = @import("rise");
const capabilities = rise.capabilities;
pub const Syscall = rise.capabilities.Syscall;

pub const arch = @import("user/arch.zig");
const core_state = @import("user/core_state.zig");
pub const CoreState = core_state.CoreState;
pub const thread = @import("user/thread.zig");
pub const process = @import("user/process.zig");
const vas = @import("user/virtual_address_space.zig");
const VirtualAddress = lib.VirtualAddress;
pub const VirtualAddressSpace = vas.VirtualAddressSpace;
pub const MMUAwareVirtualAddressSpace = vas.MMUAwareVirtualAddressSpace;

comptime {
    @export(arch._start, .{ .linkage = .Strong, .name = "_start" });
}

pub const writer = lib.Writer(void, Writer.Error, Writer.write){ .context = {} };
const Writer = extern struct {
    const syscall = Syscall(.io, .log);
    const Error = Writer.syscall.ErrorSet.Error;

    fn write(_: void, bytes: []const u8) Error!usize {
        const result = try Writer.syscall.blocking(bytes);
        return result;
    }
};

pub const std_options = struct {
    pub fn logFn(comptime level: lib.std.log.Level, comptime scope: @TypeOf(.EnumLiteral), comptime format: []const u8, args: anytype) void {
        lib.format(writer, format, args) catch unreachable;
        writer.writeByte('\n') catch unreachable;
        _ = scope;
        _ = level;
    }
};

pub fn zigPanic(message: []const u8, _: ?*lib.StackTrace, _: ?usize) noreturn {
    @call(.always_inline, panic, .{ "{s}", .{message} });
}

pub fn panic(comptime format: []const u8, arguments: anytype) noreturn {
    lib.log.scoped(.PANIC).err(format, arguments);
    while (true) {
        Syscall(.process, .exit).blocking(false) catch |err| log.err("Exit failed: {}", .{err});
    }
}

pub const Scheduler = extern struct {
    time_slice: u32,
    core_id: u32,
    core_state: CoreState,
};

pub const PhysicalMap = extern struct {
    virtual_address_space: *VirtualAddressSpace,
};

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

// Barrelfish: memobj
pub const PhysicalMemoryRegion = extern struct {};

// Barrelfish: vregion
pub const VirtualMemoryRegion = extern struct {
    virtual_address_space: *VirtualAddressSpace,
    physical_region: *PhysicalMemoryRegion,
    offset: usize,
    size: usize,
    address: VirtualAddress,
    flags: Flags,
    next: ?*VirtualMemoryRegion = null,

    pub const Flags = packed struct(u8) {
        read: bool,
        write: bool,
        execute: bool,
        caching: bool,
        preferred_page_size: u2,
        write_combining: bool,
        reserved: u1 = 0,
    };
};

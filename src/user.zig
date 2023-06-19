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
pub const PinnedState = core_state.PinnedState;
pub const libc = @import("user/libc.zig");
pub const thread = @import("user/thread.zig");
pub const process = @import("user/process.zig");
const vas = @import("user/virtual_address_space.zig");
const VirtualAddress = lib.VirtualAddress;
pub const VirtualAddressSpace = vas.VirtualAddressSpace;
pub const MMUAwareVirtualAddressSpace = vas.MMUAwareVirtualAddressSpace;

pub const PhysicalMap = @import("user/physical_map.zig").PhysicalMap;
pub const PhysicalMemoryRegion = @import("user/physical_memory_region.zig").PhysicalMemoryRegion;
pub const SlotAllocator = @import("user/slot_allocator.zig").SlotAllocator;

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

pub inline fn currentScheduler() *Scheduler {
    return arch.currentScheduler();
}

fn schedulerInitDisabled(scheduler: *arch.Scheduler) void {
    // Architecture-specific initialization
    scheduler.generic.time_slice = 1;
    // TODO: capabilities
}

pub var is_init = false;
pub var command_buffer: rise.CommandBuffer = undefined;

pub export fn start(scheduler: *arch.Scheduler, arg_init: bool) callconv(.C) noreturn {
    assert(arg_init);
    is_init = arg_init;
    if (is_init) {
        assert(scheduler.common.generic.setup_stack_lock.load(.Monotonic));
    }
    assert(scheduler.common.generic.disabled);
    scheduler.initDisabled();
    @panic("TWTQWD");
    // command_buffer = Syscall(.cpu, .get_command_buffer).blocking(&command_buffer) catch @panic("Unable to get command buffer");
}

// export fn riseInitializeDisabled(scheduler: *arch.Scheduler, arg_init: bool) callconv(.C) noreturn {
//     // TODO: delete when this code is unnecessary. In the meanwhile it counts as a sanity check
//     assert(arg_init);
//     is_init = arg_init;
//     schedulerInitDisabled(scheduler);
//     thread.initDisabled(scheduler);
// }

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
        read: bool = false,
        write: bool = false,
        execute: bool = false,
        cache_disabled: bool = false,
        preferred_page_size: u2 = 0,
        write_combining: bool = false,
        reserved: u1 = 0,
    };
};

pub const MoreCore = extern struct {
    const InitializationError = error{
        invalid_page_size,
    };

    pub fn init(page_size: usize) InitializationError!void {
        blk: inline for (lib.arch.valid_page_sizes) |valid_page_size| {
            if (valid_page_size == page_size) break :blk;
        } else {
            return InitializationError.invalid_page_size;
        }

        const morecore_state = process.getMoreCoreState();
        morecore_state.mmu_state = try MMUAwareVirtualAddressSpace.initAligned(SlotAllocator.getDefault(), lib.arch.valid_page_sizes[1], lib.arch.valid_page_sizes[0], .{ .read = true, .write = true });

        @panic("TODO: MoreCore.init");
    }

    pub const State = extern struct {
        mmu_state: MMUAwareVirtualAddressSpace,
    };
};

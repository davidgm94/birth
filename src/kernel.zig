const kernel = @This();
pub const identity = common.ExecutableIdentity.kernel;

pub const common = @import("common");
pub const context = @import("context");

pub const drivers = @import("drivers.zig");
pub const arch = @import("kernel/arch.zig");
pub const bounds = arch.Bounds;
pub const Heap = common.Heap;
comptime {
    //common.reference_all_declarations(Syscall);
    common.reference_all_declarations(arch);
}

const PhysicalAddress = common.PhysicalAddress;
const PhysicalAddressSpace = common.PhysicalAddressSpace;
const PhysicalMemoryRegion = common.PhysicalMemoryRegion;

const VirtualAddress = common.VirtualAddress;
const VirtualAddressSpace = common.VirtualAddressSpace;
const VirtualMemoryRegion = common.VirtualMemoryRegion;
const VirtualMemoryRegionWithPermissions = common.VirtualMemoryRegionWithPermissions;

const Scheduler = common.Scheduler;

pub const privilege_level = common.PrivilegeLevel.kernel;
pub var main_storage: *drivers.Filesystem = undefined;
pub var physical_address_space: PhysicalAddressSpace = undefined;
pub var virtual_address_space: VirtualAddressSpace = undefined;

pub var bootstrap_context: common.BootstrapContext = undefined;
pub var scheduler = Scheduler{
    .lock = common.arch.Spinlock.new(),
    .thread_buffer = common.Thread.Buffer{},
    .all_threads = common.Thread.List{},
    .active_threads = common.Thread.List{},
    .paused_threads = common.Thread.List{},
    .cpus = &.{},
};
pub var bootstrapping_memory: [context.page_size * 16]u8 = undefined;
pub var font: common.PSF1.Font = undefined;
pub var higher_half_direct_map: VirtualAddress = undefined;
pub var file: common.File = undefined;
pub var sections_in_memory: []VirtualMemoryRegion = undefined;

/// Define root.log_level to override the default
pub const log_level: common.log.Level = switch (common.build_mode) {
    .Debug => .debug,
    .ReleaseSafe => .debug,
    .ReleaseFast, .ReleaseSmall => .debug,
};

pub fn log(comptime level: common.log.Level, comptime scope: @TypeOf(.EnumLiteral), comptime format: []const u8, args: anytype) void {
    const scope_prefix = if (scope == .default) ": " else "(" ++ @tagName(scope) ++ "): ";
    const prefix = "[" ++ @tagName(level) ++ "] " ++ scope_prefix;
    const current_thread = common.arch.get_current_thread();
    const current_cpu = current_thread.cpu orelse while (true) {};
    const processor_id = current_cpu.id;
    common.arch.Writer.lock.acquire();
    common.arch.writer.print("[Kernel] [Core #{}] [Thread #{}] ", .{ processor_id, current_thread.id }) catch unreachable;
    common.arch.writer.writeAll(prefix) catch unreachable;
    common.arch.writer.print(format, args) catch unreachable;
    common.arch.writer.writeByte('\n') catch unreachable;
    common.arch.Writer.lock.release();
}

//var panicking: usize = 0;
pub fn panic(message: []const u8, _: ?*common.StackTrace) noreturn {
    kernel.crash("{s}", .{message});
}

pub fn crash(comptime format: []const u8, args: anytype) noreturn {
    @setCold(true);
    const crash_log = common.log.scoped(.PANIC);
    common.arch.disable_interrupts();
    crash_log.err(format, args);
    while (true) {
        asm volatile (
            \\cli
            \\hlt
            \\pause
            ::: "memory");
    }
}

pub fn TODO(src: common.SourceLocation) noreturn {
    crash("TODO: {s}:{}:{} {s}()", .{ src.file, src.line, src.column, src.fn_name });
}

pub inline fn bytes_to_pages(bytes: u64, comptime must_be_exact: common.MustBeExact) u64 {
    return common.remainder_division_maybe_exact(bytes, context.page_size, must_be_exact);
}

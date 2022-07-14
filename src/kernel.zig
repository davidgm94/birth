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
pub var memory_region = VirtualMemoryRegion.new(VirtualAddress.new(0xFFFF900000000000), 0xFFFFF00000000000 - 0xFFFF900000000000);
pub const core_memory_region = VirtualMemoryRegion.new(VirtualAddress.new(0xFFFF800100000000), 0xFFFF800200000000 - 0xFFFF800100000000);

pub var scheduler: Scheduler = undefined;
pub var bootstrapping_memory: [context.page_size * 16]u8 = undefined;
pub var font: common.PSF1.Font = undefined;
pub var higher_half_direct_map: VirtualAddress = undefined;
pub var file: common.File = undefined;
pub var sections_in_memory: []VirtualMemoryRegion = undefined;

pub var cpus: []common.arch.CPU = undefined;
pub var local_storages: []common.arch.LocalStorage = undefined;

/// Define root.log_level to override the default
pub const log_level: common.log.Level = switch (common.build_mode) {
    .Debug => .debug,
    .ReleaseSafe => .debug,
    .ReleaseFast, .ReleaseSmall => .info,
};

pub fn log(comptime level: common.log.Level, comptime scope: @TypeOf(.EnumLiteral), comptime format: []const u8, args: anytype) void {
    const scope_prefix = if (scope == .default) ": " else "(" ++ @tagName(scope) ++ "): ";

    //var time: [20]u8 = undefined; // 20 should be enough for 64 bit system
    //const buffer = time[0..];
    //const time_str = kernel.fmt.bufPrint(buffer, "{d:>6}", .{@intToFloat(f64, kernel.arch.Clock.TICK) / @intToFloat(f64, kernel.arch.HZ)}) catch @panic("Unexpected format error in root.log");
    const prefix = "[" ++ @tagName(level) ++ "] " ++ scope_prefix;

    //kernel.arch.writer.writeAll("[") catch unreachable;
    //kernel.arch.writer.writeAll(time_str) catch unreachable;
    //kernel.arch.writer.writeAll("] ") catch unreachable;
    common.arch.Writer.lock.acquire();
    kernel.arch.writer.print(prefix ++ format ++ "\n", args) catch unreachable;
    common.arch.Writer.lock.release();
}

//var panicking: usize = 0;
pub fn panic(message: []const u8, _: ?*common.StackTrace) noreturn {
    kernel.crash("{s}", .{message});
}

pub fn crash(comptime format: []const u8, args: anytype) noreturn {
    const crash_log = common.log.scoped(.PANIC);
    @setCold(true);
    common.arch.disable_interrupts();
    crash_log.err(format, args);
    while (true) {}
}

pub fn TODO(src: common.SourceLocation) noreturn {
    crash("TODO: {s}:{}:{} {s}()", .{ src.file, src.line, src.column, src.fn_name });
}

pub inline fn bytes_to_pages(bytes: u64, comptime must_be_exact: common.MustBeExact) u64 {
    return common.remainder_division_maybe_exact(bytes, context.page_size, must_be_exact);
}

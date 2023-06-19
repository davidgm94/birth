// This package provides of privileged data structures and routines to both kernel and bootloaders, for now

const lib = @import("lib");
// const PhysicalAddress = lib.PhysicalAddress;
// const VirtualAddress = lib.VirtualAddress;
// const PhysicalMemoryRegion = lib.PhysicalMemoryRegion;
// const VirtualMemoryRegion = lib.VirtualMemoryRegion;

const assert = lib.assert;
const log = lib.log;
const maxInt = lib.maxInt;
const Allocator = lib.Allocator;

const bootloader = @import("bootloader");

pub const ACPI = @import("privileged/acpi.zig");
pub const arch = @import("privileged/arch.zig");

pub const writer = E9Writer{ .context = {} };

pub const E9WriterError = error{};
pub const E9Writer = lib.Writer(void, E9WriterError, writeToE9);

fn writeToE9(_: void, bytes: []const u8) E9WriterError!usize {
    return arch.io.writeBytes(0xe9, bytes);
}

pub const default_stack_size = 0x4000;

pub const ResourceOwner = enum(u2) {
    bootloader = 0,
    kernel = 1,
    user = 2,
};

const panic_logger = lib.log.scoped(.PANIC);

inline fn exitFromQEMU(exit_code: lib.QEMU.ExitCode) noreturn {
    comptime assert(@sizeOf(lib.QEMU.ExitCode) == @sizeOf(u32));
    arch.io.write(u32, lib.QEMU.isa_debug_exit.io_base, @intFromEnum(exit_code));

    arch.stopCPU();
}

pub inline fn shutdown(exit_code: lib.QEMU.ExitCode) noreturn {
    if (lib.is_test) {
        exitFromQEMU(exit_code);
    } else {
        arch.stopCPU();
    }
}

pub const Mapping = extern struct {
    physical: lib.PhysicalAddress = lib.PhysicalAddress.invalid(),
    virtual: lib.VirtualAddress = .null,
    size: u64 = 0,
    flags: Flags = .{},
    reserved: u32 = 0,

    pub const Flags = packed struct(u32) {
        write: bool = false,
        cache_disable: bool = false,
        global: bool = false,
        execute: bool = false,
        user: bool = false,
        secret: bool = false,
        reserved: u26 = 0,

        pub inline fn empty() Flags {
            return .{};
        }

        pub inline fn toArchitectureSpecific(flags: Flags) arch.paging.MemoryFlags {
            return arch.paging.newFlags(flags);
        }
    };
};

pub const PageAllocator = struct {
    allocate: *const fn (context: ?*anyopaque, size: u64, alignment: u64, allocate_options: AllocateOptions) Allocator.Allocate.Error!lib.PhysicalMemoryRegion,
    context: ?*anyopaque,
    context_type: ContextType,
    reserved: u32 = 0,

    pub const AllocatePageTablesOptions = packed struct {
        count: u16 = 1,
        level: arch.paging.Level,
        user: bool,
    };

    pub inline fn allocatePageTable(page_allocator: PageAllocator, options: AllocatePageTablesOptions) !lib.PhysicalMemoryRegion {
        const result = try page_allocator.allocate(page_allocator.context, arch.paging.page_table_size, arch.paging.page_table_alignment, .{
            .count = options.count,
            .level = options.level,
            .level_valid = true,
            .user = options.user,
        });
        return result;
    }

    pub const AllocateOptions = packed struct {
        count: u16 = 1,
        space_waste_allowed_to_guarantee_alignment: u8 = 0,
        level: arch.paging.Level = undefined,
        level_valid: bool = false,
        user: bool = false,
    };

    const ContextType = enum(u32) {
        invalid = 0,
        bootloader = 1,
        cpu = 2,
    };
};

// This package provides of privileged data structures and routines to both kernel and bootloaders, for now

const lib = @import("lib");
const assert = lib.assert;
const log = lib.log;
const maxInt = lib.maxInt;
const Allocator = lib.Allocator;

const bootloader = @import("bootloader");

pub const ACPI = @import("privileged/acpi.zig");
pub const arch = @import("privileged/arch.zig");

pub const E9WriterError = error{};
pub const E9Writer = lib.Writer(void, E9WriterError, writeToE9);
pub const writer = E9Writer{ .context = {} };

fn writeToE9(_: void, bytes: []const u8) E9WriterError!usize {
    return arch.io.writeBytes(0xe9, bytes);
}

pub const default_stack_size = 0x4000;

pub const ResourceOwner = enum(u2) {
    bootloader = 0,
    kernel = 1,
    user = 2,
};

// pub const RBED = struct {
//     queue_head: ?*CoreDirectorData,
//     queue_tail: ?*CoreDirectorData,
//     // TODO: more stuff
// };

const panic_logger = lib.log.scoped(.PANIC);

pub inline fn exitFromQEMU(exit_code: lib.QEMU.ExitCode) noreturn {
    log.info("Exiting with {s}", .{@tagName(exit_code)});
    comptime assert(@sizeOf(lib.QEMU.ExitCode) == @sizeOf(u32));
    arch.io.write(u32, lib.QEMU.isa_debug_exit.io_base, @enumToInt(exit_code));

    arch.stopCPU();
}

pub const PhysicalAddress = enum(u64) {
    null = 0,
    _,
    const PA = @This();

    pub inline fn new(address: u64) PA {
        if (address >= lib.config.cpu_driver_higher_half_address) @panic("Trying to write a higher half virtual address value into a physical address");
        return @intToEnum(PA, address);
    }

    pub inline fn maybeInvalid(address: u64) PA {
        return @intToEnum(PA, address);
    }

    pub inline fn invalid() PA {
        return maybeInvalid(0);
    }

    pub inline fn value(physical_address: PA) u64 {
        return @enumToInt(physical_address);
    }

    pub inline fn toIdentityMappedVirtualAddress(physical_address: PA) VirtualAddress {
        return VirtualAddress.new(physical_address.value());
    }

    pub inline fn toHigherHalfVirtualAddress(physical_address: PA) VirtualAddress {
        return physical_address.toIdentityMappedVirtualAddress().offset(lib.config.cpu_driver_higher_half_address);
    }

    pub inline fn addOffset(physical_address: *PA, asked_offset: u64) void {
        physical_address.* = physical_address.offset(asked_offset);
    }

    pub inline fn offset(physical_address: PA, asked_offset: u64) PA {
        return @intToEnum(PA, @enumToInt(physical_address) + asked_offset);
    }

    pub inline fn isAligned(physical_address: PA, alignment: u64) bool {
        const alignment_mask = alignment - 1;
        return physical_address.value() & alignment_mask == 0;
    }
};

pub const VirtualAddress = enum(u64) {
    null = 0,
    _,

    const VA = @This();

    pub inline fn new(address: u64) VA {
        return @intToEnum(VA, address);
    }

    pub inline fn value(virtual_address: VA) u64 {
        return @enumToInt(virtual_address);
    }

    pub inline fn access(virtual_address: VA, comptime Ptr: type) Ptr {
        return @intToPtr(Ptr, lib.safeArchitectureCast(virtual_address.value()));
    }

    pub inline fn isValid(virtual_address: VA) bool {
        _ = virtual_address;
        return true;
    }

    pub inline fn offset(virtual_address: VA, asked_offset: u64) VA {
        return @intToEnum(VA, virtual_address.value() + asked_offset);
    }

    pub inline fn negativeOffset(virtual_address: VA, asked_offset: u64) VA {
        return @intToEnum(VA, virtual_address.value() - asked_offset);
    }

    pub inline fn toPhysicalAddress(virtual_address: VA) PhysicalAddress {
        if (virtual_address.value() < lib.config.cpu_driver_higher_half_address) @panic("toPhysicalAddress");
        return @intToEnum(PhysicalAddress, virtual_address.value() - lib.config.cpu_driver_higher_half_address);
    }
};

pub const PhysicalMemoryRegion = extern struct {
    address: PhysicalAddress,
    size: u64,

    const PMR = @This();

    pub inline fn new(address: PhysicalAddress, size: u64) PMR {
        return .{
            .address = address,
            .size = size,
        };
    }

    pub inline fn fromSlice(slice: []u8) PMR {
        return .{
            .address = PhysicalAddress.new(@ptrToInt(slice.ptr)),
            .size = slice.len,
        };
    }

    pub inline fn toIdentityMappedVirtualAddress(physical_memory_region: PMR) VirtualMemoryRegion {
        return .{
            .address = physical_memory_region.address.toIdentityMappedVirtualAddress(),
            .size = physical_memory_region.size,
        };
    }

    pub inline fn toHigherHalfVirtualAddress(physical_memory_region: PMR) VirtualMemoryRegion {
        return .{
            .address = physical_memory_region.address.toHigherHalfVirtualAddress(),
            .size = physical_memory_region.size,
        };
    }

    pub inline fn offset(physical_memory_region: PMR, asked_offset: u64) PMR {
        const address = physical_memory_region.address.offset(asked_offset);
        const size = physical_memory_region.size - asked_offset;

        return .{
            .address = address,
            .size = size,
        };
    }

    pub inline fn takeSlice(physical_memory_region: PMR, asked_size: u64) PMR {
        if (asked_size >= physical_memory_region.size) @panic("asked size is greater than size of region");

        return .{
            .address = physical_memory_region.address,
            .size = asked_size,
        };
    }

    pub inline fn overlaps(physical_memory_region: PMR, other: PMR) bool {
        if (other.address.value() >= physical_memory_region.address.offset(physical_memory_region.size).value()) return false;
        if (other.address.offset(other.size).value() <= physical_memory_region.address.value()) return false;

        const region_inside = other.address.value() >= physical_memory_region.address.value() and other.address.offset(other.size).value() <= physical_memory_region.address.offset(physical_memory_region.size).value();
        const region_overlap_left = other.address.value() <= physical_memory_region.address.value() and other.address.offset(other.size).value() > physical_memory_region.address.value();
        const region_overlap_right = other.address.value() < physical_memory_region.address.offset(physical_memory_region.size).value() and other.address.offset(other.size).value() > physical_memory_region.address.offset(physical_memory_region.size).value();
        return region_inside or region_overlap_left or region_overlap_right;
    }
};

pub const VirtualMemoryRegion = extern struct {
    address: VirtualAddress,
    size: u64,

    const VMR = @This();

    pub inline fn access(virtual_memory_region: VMR, comptime T: type) []T {
        const slice_len = @divExact(virtual_memory_region.size, @sizeOf(T));
        const result = virtual_memory_region.address.access([*]T)[0..lib.safeArchitectureCast(slice_len)];
        return result;
    }
};

pub const Mapping = extern struct {
    physical: PhysicalAddress = PhysicalAddress.invalid(),
    virtual: VirtualAddress = .null,
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
    allocate: *const fn (context: ?*anyopaque, size: u64, alignment: u64, allocate_options: AllocateOptions) Allocator.Allocate.Error!PhysicalMemoryRegion,
    context: ?*anyopaque,
    context_type: ContextType,
    reserved: u32 = 0,

    pub const AllocatePageTablesOptions = packed struct {
        count: u16 = 1,
        level: arch.paging.Level,
        user: bool,
    };

    pub inline fn allocatePageTable(page_allocator: PageAllocator, options: AllocatePageTablesOptions) !PhysicalMemoryRegion {
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

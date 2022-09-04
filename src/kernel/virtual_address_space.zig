const VirtualAddressSpace = @This();

const std = @import("../common/std.zig");

const arch = @import("arch/common.zig");
const Heap = @import("heap.zig");
const kernel = @import("kernel.zig");
const log = std.log.scoped(.VirtualAddressSpace);
const PhysicalAddress = @import("physical_address.zig");
const PhysicalAddressSpace = @import("physical_address_space.zig");
const PhysicalMemoryRegion = @import("physical_memory_region.zig");
const PrivilegeLevel = @import("scheduler_common.zig").PrivilegeLevel;
const Spinlock = @import("spinlock.zig");
const VAS = arch.VAS;
const VirtualAddress = @import("virtual_address.zig");
const VirtualMemoryRegion = @import("virtual_memory_region.zig");

arch: VAS,
privilege_level: PrivilegeLevel,
heap: Heap,
lock: Spinlock,
initialized: bool,

/// This is going to return an identitty-mapped virtual address pointer and it is only intended to use for the
/// kernel address space
pub fn initialize_kernel_address_space(virtual_address_space: *VirtualAddressSpace, physical_address_space: *PhysicalAddressSpace) ?void {
    // TODO: defer memory free when this produces an error
    const arch_virtual_space = VAS.new(physical_address_space) orelse return null;
    // TODO: Maybe consume just the necessary space? We are doing this to avoid branches in the kernel heap allocator
    virtual_address_space.* = VirtualAddressSpace{
        .arch = arch_virtual_space,
        .privilege_level = .kernel,
        .heap = Heap.new(virtual_address_space),
        .lock = Spinlock{},
        .initialized = false,
    };
}

pub fn bootstrapping() VirtualAddressSpace {
    const bootstrap_arch_specific_vas = VAS.bootstrapping();
    return VirtualAddressSpace{
        .arch = bootstrap_arch_specific_vas,
        .privilege_level = .kernel,
        .heap = Heap{},
        .lock = Spinlock{},
        .initialized = false,
    };
}

pub fn initialize_user_address_space(virtual_address_space: *VirtualAddressSpace, physical_address_space: *PhysicalAddressSpace, kernel_address_space: *VirtualAddressSpace) ?void {
    // TODO: defer memory free when this produces an error
    const arch_virtual_space = VAS.new(physical_address_space) orelse return null;
    // TODO: Maybe consume just the necessary space? We are doing this to avoid branches in the kernel heap allocator
    virtual_address_space.* = VirtualAddressSpace{
        .arch = arch_virtual_space,
        .privilege_level = .user,
        .heap = Heap.new(virtual_address_space),
        .lock = Spinlock{},
        .initialized = false,
    };

    virtual_address_space.arch.map_kernel_address_space_higher_half(kernel_address_space);
}

pub fn copy_to_new(old: *VirtualAddressSpace, new: *VirtualAddressSpace) void {
    new.* = old.*;
    new.heap.allocator.ptr = new;
}

pub fn allocate(virtual_address_space: *VirtualAddressSpace, byte_count: u64, maybe_specific_address: ?VirtualAddress, flags: Flags) !VirtualAddress {
    const result = try virtual_address_space.allocate_extended(byte_count, maybe_specific_address, flags);
    return result.virtual_address;
}

const Result = struct {
    physical_address: PhysicalAddress,
    virtual_address: VirtualAddress,
};

pub fn allocate_extended(virtual_address_space: *VirtualAddressSpace, byte_count: u64, maybe_specific_address: ?VirtualAddress, flags: Flags) !Result {
    virtual_address_space.lock.acquire();
    defer virtual_address_space.lock.release();
    const page_count = std.bytes_to_pages(byte_count, arch.page_size, .must_be_exact);
    const physical_address = kernel.physical_address_space.allocate(page_count) orelse return std.Allocator.Error.OutOfMemory;

    const virtual_address = blk: {
        if (maybe_specific_address) |specific_address| {
            std.assert(!flags.user == specific_address.is_higher_half());
            break :blk specific_address;
        } else {
            if (flags.user) {
                break :blk VirtualAddress.new(physical_address.value);
            } else {
                break :blk physical_address.to_higher_half_virtual_address();
            }
        }
    };

    if (flags.user) std.assert(virtual_address_space.translate_address_extended(virtual_address, AlreadyLocked.yes) == null);

    const physical_region = PhysicalMemoryRegion.new(physical_address, page_count * arch.page_size);
    virtual_address_space.map_physical_region_extended(physical_region, virtual_address, flags, AlreadyLocked.yes);

    return Result{
        .physical_address = physical_address,
        .virtual_address = virtual_address,
    };
}

pub fn map(virtual_address_space: *VirtualAddressSpace, physical_address: PhysicalAddress, virtual_address: VirtualAddress, flags: Flags) void {
    map_extended(virtual_address_space, physical_address, virtual_address, flags, AlreadyLocked.no);
}

const AlreadyLocked = enum {
    no,
    yes,
};

const debug_with_translate_address = false;

fn map_extended(virtual_address_space: *VirtualAddressSpace, physical_address: PhysicalAddress, virtual_address: VirtualAddress, flags: Flags, comptime already_locked: AlreadyLocked) void {
    if (already_locked == .yes) {
        std.assert(virtual_address_space.lock.status != 0);
    } else {
        virtual_address_space.lock.acquire();
    }
    defer {
        if (already_locked == .no) {
            virtual_address_space.lock.release();
        }
    }
    virtual_address_space.arch.map(physical_address, virtual_address, flags.to_arch_specific());
    if (debug_with_translate_address) {
        const new_physical_address = virtual_address_space.translate_address_extended(virtual_address, AlreadyLocked.yes) orelse @panic("address not present");
        std.assert(new_physical_address.is_valid());
        std.assert(new_physical_address.is_equal(physical_address));
    }
}

pub fn translate_address(virtual_address_space: *VirtualAddressSpace, virtual_address: VirtualAddress) ?PhysicalAddress {
    return translate_address_extended(virtual_address_space, virtual_address, AlreadyLocked.no);
}

fn translate_address_extended(virtual_address_space: *VirtualAddressSpace, virtual_address: VirtualAddress, already_locked: AlreadyLocked) ?PhysicalAddress {
    if (already_locked == .yes) {
        std.assert(virtual_address_space.lock.status != 0);
    } else {
        virtual_address_space.lock.acquire();
    }
    defer {
        if (already_locked == .no) {
            virtual_address_space.lock.release();
        }
    }

    const result = virtual_address_space.arch.translate_address(virtual_address);
    return result;
}

pub fn make_current(virtual_address_space: *VirtualAddressSpace) void {
    virtual_address_space.arch.make_current();
}

// TODO: make this efficient
pub fn map_virtual_region(virtual_address_space: *VirtualAddressSpace, virtual_region: VirtualMemoryRegion, base_physical_address: PhysicalAddress, flags: Flags) void {
    virtual_address_space.lock.acquire();
    defer virtual_address_space.lock.release();

    var physical_address = base_physical_address;
    var virtual_address = virtual_region.address;
    const page_size = arch.page_size;
    std.assert(std.is_aligned(physical_address.value, page_size));
    std.assert(std.is_aligned(virtual_address.value, page_size));
    std.assert(std.is_aligned(virtual_region.size, page_size));

    var size: u64 = 0;

    while (size < virtual_region.size) : (size += page_size) {
        virtual_address_space.map_extended(physical_address, virtual_address, flags, AlreadyLocked.yes);
        physical_address.value += page_size;
        virtual_address.value += page_size;
    }
}

pub fn map_physical_region(virtual_address_space: *VirtualAddressSpace, physical_region: PhysicalMemoryRegion, base_virtual_address: VirtualAddress, flags: Flags) void {
    return map_physical_region_extended(virtual_address_space, physical_region, base_virtual_address, flags, AlreadyLocked.no);
}

fn map_physical_region_extended(virtual_address_space: *VirtualAddressSpace, physical_region: PhysicalMemoryRegion, base_virtual_address: VirtualAddress, flags: Flags, already_locked: AlreadyLocked) void {
    if (already_locked == .yes) {
        std.assert(virtual_address_space.lock.status != 0);
    } else {
        virtual_address_space.lock.acquire();
    }
    defer {
        if (already_locked == .no) {
            virtual_address_space.lock.release();
        }
    }

    var physical_address = physical_region.address;
    var virtual_address = base_virtual_address;
    const page_size = arch.page_size;
    std.assert(std.is_aligned(physical_address.value, page_size));
    std.assert(std.is_aligned(virtual_address.value, page_size));
    std.assert(std.is_aligned(physical_region.size, page_size));

    var size: u64 = 0;

    while (size < physical_region.size) : (size += page_size) {
        virtual_address_space.map_extended(physical_address, virtual_address, flags, AlreadyLocked.yes);
        physical_address.value += page_size;
        virtual_address.value += page_size;
    }
}

pub inline fn is_current(virtual_address_space: *VirtualAddressSpace) bool {
    return virtual_address_space.arch.is_current();
}

pub const Flags = packed struct {
    write: bool = false,
    cache_disable: bool = false,
    accessed: bool = false,
    global: bool = false,
    execute: bool = false,
    user: bool = false,

    pub inline fn empty() Flags {
        return std.zeroes(Flags);
    }

    pub inline fn to_arch_specific(flags: Flags) VAS.MemoryFlags {
        return VAS.new_flags(flags);
    }
};

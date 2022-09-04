const VirtualAddressSpace = @This();

const std = @import("../common/std.zig");

const arch = @import("arch/common.zig");
const AVL = @import("../common/avl.zig");
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

// TODO: Make this safe
var tree_buffer: [1024 * 1024 * 50]u8 = undefined;

arch: VAS,
privilege_level: PrivilegeLevel,
heap: Heap,
lock: Spinlock,
free_regions_by_address: AVL.Tree(Region) = .{},
free_regions_by_size: AVL.Tree(Region) = .{},
used_regions: AVL.Tree(Region) = .{},

/// This is going to return an identitty-mapped virtual address pointer and it is only intended to use for the
/// kernel address space
pub fn initialize_kernel_address_space(virtual_address_space: *VirtualAddressSpace, physical_address_space: *PhysicalAddressSpace) ?void {
    // TODO: defer memory free when this produces an error
    // TODO: Maybe consume just the necessary space? We are doing this to avoid branches in the kernel heap allocator
    virtual_address_space.* = VirtualAddressSpace{
        .arch = undefined,
        .privilege_level = .kernel,
        .heap = Heap.new(virtual_address_space),
        .lock = Spinlock{},
    };
    VAS.new(virtual_address_space, physical_address_space);
}

pub fn bootstrapping() VirtualAddressSpace {
    const bootstrap_arch_specific_vas = VAS.bootstrapping();
    return VirtualAddressSpace{
        .arch = bootstrap_arch_specific_vas,
        .privilege_level = .kernel,
        .heap = Heap{},
        .lock = Spinlock{},
    };
}

pub fn initialize_user_address_space(virtual_address_space: *VirtualAddressSpace, physical_address_space: *PhysicalAddressSpace, kernel_address_space: *VirtualAddressSpace) void {
    // TODO: defer memory free when this produces an error
    // TODO: Maybe consume just the necessary space? We are doing this to avoid branches in the kernel heap allocator
    virtual_address_space.* = VirtualAddressSpace{
        .arch = undefined,
        .privilege_level = .user,
        .heap = Heap.new(virtual_address_space),
        .lock = Spinlock{},
    };
    VAS.new(virtual_address_space, physical_address_space);

    virtual_address_space.arch.map_kernel_address_space_higher_half(kernel_address_space);
}

pub fn copy_to_new(old: *VirtualAddressSpace, new: *VirtualAddressSpace) void {
    new.* = old.*;
    new.heap.allocator.ptr = new;
}

pub fn allocate(virtual_address_space: *VirtualAddressSpace, byte_count: u64, maybe_specific_address: ?VirtualAddress, flags: Flags) !VirtualAddress {
    const result = try virtual_address_space.allocate_extended(byte_count, maybe_specific_address, flags, AlreadyLocked.no);
    return result.virtual_address;
}

const Result = struct {
    physical_address: PhysicalAddress,
    virtual_address: VirtualAddress,
};

pub fn allocate_extended(virtual_address_space: *VirtualAddressSpace, byte_count: u64, maybe_specific_address: ?VirtualAddress, flags: Flags, comptime already_locked: AlreadyLocked) !Result {
    if (already_locked == .no) virtual_address_space.lock.acquire();
    defer if (already_locked == .no) virtual_address_space.lock.release();

    const page_count = @divFloor(byte_count, arch.page_size);
    const physical_address = kernel.physical_address_space.allocate(page_count) orelse return std.Allocator.Error.OutOfMemory;

    const virtual_address = blk: {
        if (maybe_specific_address) |specific_address| {
            std.assert(flags.user == (specific_address.value < kernel.higher_half_direct_map.value));
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

    try virtual_address_space.map_extended(physical_address, virtual_address, page_count, flags, AlreadyLocked.yes);

    return Result{
        .physical_address = physical_address,
        .virtual_address = virtual_address,
    };
}

pub const MapError = error{
    already_present,
};

pub fn map(virtual_address_space: *VirtualAddressSpace, base_physical_address: PhysicalAddress, base_virtual_address: VirtualAddress, page_count: u64, flags: Flags) MapError!void {
    try map_extended(virtual_address_space, base_physical_address, base_virtual_address, page_count, flags, AlreadyLocked.no);
}

pub const AlreadyLocked = enum {
    no,
    yes,
};

const debug_with_translate_address = false;

fn map_extended(virtual_address_space: *VirtualAddressSpace, base_physical_address: PhysicalAddress, base_virtual_address: VirtualAddress, page_count: u64, flags: Flags, comptime already_locked: AlreadyLocked) MapError!void {
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

    var physical_address = base_physical_address;
    var virtual_address = base_virtual_address;

    var page_i: u64 = 0;
    while (page_i < page_count) : (page_i += 1) {
        defer physical_address.value += arch.page_size;
        defer virtual_address.value += arch.page_size;

        try VAS.map(virtual_address_space, physical_address, virtual_address, flags.to_arch_specific());
        if (debug_with_translate_address) {
            const new_physical_address = virtual_address_space.translate_address_extended(virtual_address, AlreadyLocked.yes) orelse @panic("address not present");
            std.assert(new_physical_address.is_valid());
            std.assert(new_physical_address.is_equal(physical_address));
        }
    }

    if (kernel.memory_initialized) {
        virtual_address_space.track(virtual_address, physical_address, page_count);
    }
}

pub fn track_used_region(virtual_address_space: *VirtualAddressSpace, region: *Region) void {
    virtual_address_space.used_regions.insert(&region.by_address, region, region.address, .panic);
}

pub fn track(virtual_address_space: *VirtualAddressSpace, virtual_address: VirtualAddress, physical_address: PhysicalAddress, page_count: u64) void {
    _ = virtual_address_space;
    _ = virtual_address;
    _ = physical_address;
    _ = page_count;
    @panic("TODO");
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

pub inline fn make_current(virtual_address_space: *VirtualAddressSpace) void {
    virtual_address_space.arch.make_current();
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

pub const Region = struct {
    address: VirtualAddress,
    page_count: u64,
    flags: Flags,
    by_address: AVL.Tree(Region).Item = .{},
    by_size: AVL.Tree(Region).Item = .{},
};

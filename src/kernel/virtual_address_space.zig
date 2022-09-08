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

arch: VAS.Specific,
privilege_level: PrivilegeLevel,
heap: Heap,
lock: Spinlock,
free_regions: std.ArrayList(Region) = .{},
used_regions: std.ArrayList(Region) = .{},

pub fn from_current(virtual_address_space: *VirtualAddressSpace) void {
    VAS.from_current(virtual_address_space);
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
    VAS.new(virtual_address_space, physical_address_space, kernel.higher_half_direct_map.value);

    VAS.map_kernel_address_space_higher_half(virtual_address_space, kernel_address_space);
}

pub fn copy_to_new(old: *VirtualAddressSpace, new: *VirtualAddressSpace) void {
    new.* = old.*;
    new.heap.allocator.ptr = new;
}

pub fn allocate(virtual_address_space: *VirtualAddressSpace, byte_count: u64, maybe_specific_address: ?VirtualAddress, flags: Flags) !VirtualAddress {
    std.assert(kernel.memory_initialized);
    const result = try virtual_address_space.allocate_extended(byte_count, maybe_specific_address, flags, AlreadyLocked.no, false, 0);
    return result.virtual_address;
}

const Result = struct {
    physical_address: PhysicalAddress,
    virtual_address: VirtualAddress,
};

pub fn allocate_extended(virtual_address_space: *VirtualAddressSpace, byte_count: u64, maybe_specific_address: ?VirtualAddress, flags: Flags, comptime already_locked: AlreadyLocked, comptime is_bootstrapping: bool, kernel_higher_half_map: u64) !Result {
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
                break :blk if (is_bootstrapping) physical_address.to_virtual_address_with_offset(kernel_higher_half_map) else physical_address.to_higher_half_virtual_address();
            }
        }
    };

    // INFO: when allocating for userspace, virtual address spaces should be bootstrapped and not require this boolean value to be true
    if (flags.user) std.assert(virtual_address_space.translate_address_extended(virtual_address, AlreadyLocked.yes, false) == null);

    try virtual_address_space.map_extended(physical_address, virtual_address, page_count, flags, AlreadyLocked.yes, is_bootstrapping, kernel_higher_half_map);

    return Result{
        .physical_address = physical_address,
        .virtual_address = virtual_address,
    };
}

pub const MapError = error{
    already_present,
};

pub fn map(virtual_address_space: *VirtualAddressSpace, base_physical_address: PhysicalAddress, base_virtual_address: VirtualAddress, page_count: u64, flags: Flags) MapError!void {
    std.assert(kernel.memory_initialized);
    try map_extended(virtual_address_space, base_physical_address, base_virtual_address, page_count, flags, AlreadyLocked.no, false, 0);
}

pub const AlreadyLocked = enum {
    no,
    yes,
};

const debug_with_translate_address = false;

pub fn map_extended(virtual_address_space: *VirtualAddressSpace, base_physical_address: PhysicalAddress, base_virtual_address: VirtualAddress, page_count: u64, flags: Flags, comptime already_locked: AlreadyLocked, comptime is_bootstrapping: bool, higher_half_direct_map: u64) MapError!void {
    if (base_virtual_address.value <= 0xffff80007ffe2000 and base_virtual_address.offset(page_count * arch.page_size).value > 0xffff80007ffe2000) {
        var i: u64 = 0;
        while (i < 10) : (i += 1) {
            log.debug("heeeeeeeeeeeeeeeeeeeeeeeeeeeeeeereeeeeeeeeeeeee", .{});
        }
    }
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

    if (!is_bootstrapping) blk: {
        const region = Region{
            .address = virtual_address,
            .page_count = page_count,
            .flags = flags,
        };

        var recording_virtual_address_space = if (base_virtual_address.value >= kernel.higher_half_direct_map.value) &kernel.virtual_address_space else virtual_address_space;

        for (recording_virtual_address_space.free_regions.items) |*free_region, free_region_i| {
            if (free_region.contains(region)) {
                log.debug("Contained", .{});
                if (region.address.value == free_region.address.value) {
                    std.assert(free_region.page_count >= region.page_count);
                    if (free_region.page_count > region.page_count) {
                        free_region.address.value += region.page_count * arch.page_size;
                        free_region.page_count -= region.page_count;
                    } else if (free_region.page_count == region.page_count) {
                        log.debug("deleting by swap remove", .{});
                        _ = recording_virtual_address_space.free_regions.swapRemove(free_region_i);
                    } else {
                        @panic("Container region is smaller than contained region");
                    }

                    recording_virtual_address_space.used_regions.append(kernel.virtual_address_space.heap.allocator, region) catch unreachable;

                    break :blk;
                } else {
                    @panic("Wtf");
                }
            }
        }

        @panic("wtf no free space");
    }

    var page_i: u64 = 0;
    while (page_i < page_count) : (page_i += 1) {
        defer physical_address.value += arch.page_size;
        defer virtual_address.value += arch.page_size;

        try VAS.map(virtual_address_space, physical_address, virtual_address, flags.to_arch_specific(), is_bootstrapping, higher_half_direct_map);
        if (debug_with_translate_address) {
            const new_physical_address = virtual_address_space.translate_address_extended(virtual_address, AlreadyLocked.yes, is_bootstrapping, higher_half_direct_map) orelse @panic("address not present");
            std.assert(new_physical_address.is_valid());
            std.assert(new_physical_address.is_equal(physical_address));
        }
    }

    //if (kernel.memory_initialized) {
    //virtual_address_space.track(virtual_address, physical_address, page_count);
    //}
}

pub fn translate_address(virtual_address_space: *VirtualAddressSpace, virtual_address: VirtualAddress) ?PhysicalAddress {
    return translate_address_extended(virtual_address_space, virtual_address, AlreadyLocked.no, false);
}

fn translate_address_extended(virtual_address_space: *VirtualAddressSpace, virtual_address: VirtualAddress, already_locked: AlreadyLocked, comptime is_bootstrapping: bool) ?PhysicalAddress {
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

    const result = VAS.translate_address(virtual_address_space, virtual_address, is_bootstrapping);
    return result;
}

pub inline fn make_current(virtual_address_space: *VirtualAddressSpace) void {
    VAS.make_current(virtual_address_space);
}

pub inline fn is_current(virtual_address_space: *VirtualAddressSpace) bool {
    return VAS.is_current(virtual_address_space);
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

pub fn add_used_region(virtual_address_space: *VirtualAddressSpace, region: Region) !void {
    if (region.is_valid_new_region_at_bootstrapping(virtual_address_space)) {
        try virtual_address_space.used_regions.append(kernel.virtual_address_space.heap.allocator, region);
    } else {
        @panic("Invalid region");
    }
}

pub fn add_free_region(virtual_address_space: *VirtualAddressSpace, region: Region) !void {
    if (region.is_valid_new_region_at_bootstrapping(virtual_address_space)) {
        try virtual_address_space.free_regions.append(kernel.virtual_address_space.heap.allocator, region);
    } else {
        @panic("Invalid region");
    }
}

pub const Region = struct {
    address: VirtualAddress,
    page_count: u64,
    flags: Flags,

    pub fn is_valid_new_region_at_bootstrapping(region: Region, virtual_address_space: *VirtualAddressSpace) bool {
        const region_base = region.address.value;
        const region_top = region.address.offset(arch.page_size * region.page_count).value;

        for (virtual_address_space.used_regions.items) |used_region| {
            if (used_region.overlap(region_base, region_top)) {
                log.err("Overlap detected. Region: (0x{x}, 0x{x}). Used: (0x{x}, 0x{x})", .{ region_base, region_top, used_region.address.value, used_region.address.offset(arch.page_size * used_region.page_count).value });
                return false;
            }
        }

        for (virtual_address_space.free_regions.items) |free_region| {
            if (free_region.overlap(region_base, region_top)) {
                log.err("Overlap detected. Region: (0x{x}, 0x{x}). Free: (0x{x}, 0x{x})", .{ region_base, region_top, free_region.address.value, free_region.address.offset(arch.page_size * free_region.page_count).value });
                return false;
            }
        }

        return true;
    }

    inline fn overlap(region: Region, region_base: u64, region_top: u64) bool {
        const other_base = region.address.value;
        const other_top = region.address.offset(arch.page_size * region.page_count).value;

        if (region_base <= other_base and region_top >= other_top) {
            log.debug("Reason 1", .{});
            return true;
        } else if (other_base <= region_base and other_top >= region_top) {
            log.debug("Reason 2", .{});
            return true;
        } else if (region_base <= other_base) {
            if (region_top > other_base) {
                log.debug("Reason 3", .{});
                return true;
            }
        } else if (other_base <= region_base) {
            if (other_top > region_base) {
                log.debug("Reason 4", .{});
                return true;
            }
        }

        return false;
    }

    inline fn contains(container: Region, contained: Region) bool {
        log.debug("(0x{x}, 0x{x}) contains (0x{x}, 0x{x})?", .{ container.address.value, container.address.offset(arch.page_size * container.page_count).value, contained.address.value, contained.address.offset(arch.page_size * contained.page_count).value });
        if (container.address.offset(container.page_count * arch.page_size).value <= contained.address.value) {
            log.debug("contain1", .{});
            return false;
        }
        if (contained.address.offset(contained.page_count * arch.page_size).value <= container.address.value) {
            log.debug("contain2", .{});
            return false;
        }
        if (container.address.value < contained.address.value) {
            @panic("foo1");
        } else if (container.address.value > contained.address.value) {
            @panic("foo2");
        } else {
            if (container.page_count < contained.page_count) @panic("Region overlap but it is too big");
            return true;
        }
    }
};

pub fn map_reserved_region(virtual_address_space: *VirtualAddressSpace, physical_address: PhysicalAddress, virtual_address: VirtualAddress, page_count: u64, flags: Flags) void {
    std.assert(virtual_address_space == &kernel.virtual_address_space);
    // Fake a free region
    virtual_address_space.free_regions.append(virtual_address_space.heap.allocator, VirtualAddressSpace.Region{
        .address = virtual_address,
        .page_count = page_count,
        .flags = flags,
    }) catch unreachable;
    kernel.virtual_address_space.map(physical_address, virtual_address, page_count, flags) catch @panic("Unable to map reserved region");
}

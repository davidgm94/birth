const VirtualAddressSpace = @This();

const common = @import("common");
const Allocator = common.CustomAllocator;
const ArrayList = common.ArrayList;
const assert = common.assert;
const is_aligned = common.is_aligned;
const ListFile = common.List;
const log = common.log.scoped(.VirtualAddressSpace);
const zeroes = common.zeroes;

const RNU = @import("RNU");
const Heap = RNU.Heap;
const panic = RNU.panic;
const PhysicalAddress = RNU.PhysicalAddress;
const PrivilegeLevel = RNU.PrivilegeLevel;
const Spinlock = RNU.Spinlock;
const VirtualAddress = RNU.VirtualAddress;

const kernel = @import("kernel");

const arch = @import("arch");
const VAS = arch.VAS;

id: u64,
arch: VAS.Specific,
privilege_level: PrivilegeLevel,
heap: Heap,
lock: Spinlock,
free_regions: ArrayList(Region) = .{},
used_regions: ArrayList(Region) = .{},

pub fn from_current(virtual_address_space: *VirtualAddressSpace) void {
    VAS.from_current(virtual_address_space);
}

pub fn initialize_user_address_space(virtual_address_space: *VirtualAddressSpace) void {
    // TODO: defer memory free when this produces an error
    // TODO: Maybe consume just the necessary space? We are doing this to avoid branches in the kernel heap allocator
    virtual_address_space.* = VirtualAddressSpace{
        .id = virtual_address_space.id,
        .arch = undefined,
        .privilege_level = .user,
        .heap = Heap.new(virtual_address_space),
        .lock = Spinlock{},
    };

    VAS.init_user(virtual_address_space);

    //const graphics = virtual_address_space.translate_address() orelse unreachable;
}

pub fn copy_to_new(old: *VirtualAddressSpace, new: *VirtualAddressSpace) void {
    new.* = old.*;
    new.heap.allocator.ptr = new;
}

pub fn allocate(virtual_address_space: *VirtualAddressSpace, byte_count: u64, maybe_specific_address: ?VirtualAddress, flags: Flags) !VirtualAddress {
    if (kernel.config.safe_slow) {
        assert(kernel.memory_initialized);
    }
    const result = try virtual_address_space.allocate_extended(byte_count, maybe_specific_address, flags, AlreadyLocked.no);
    return result.virtual_address;
}

const Result = struct {
    physical_address: PhysicalAddress,
    virtual_address: VirtualAddress,
};

pub fn allocate_extended(virtual_address_space: *VirtualAddressSpace, byte_count: u64, maybe_specific_address: ?VirtualAddress, flags: Flags, comptime already_locked: AlreadyLocked) !Result {
    if (already_locked == .no) {
        virtual_address_space.lock.acquire();
    }
    defer {
        if (already_locked == .no) {
            virtual_address_space.lock.release();
        }
    }

    const page_count = @divFloor(byte_count, arch.page_size);
    const page_aligned_size = page_count * arch.page_size;
    const physical_region = kernel.physical_address_space.allocate_pages(arch.page_size, page_count, .{ .zeroed = true }) orelse return Allocator.Error.OutOfMemory;

    const virtual_address = blk: {
        if (maybe_specific_address) |specific_address| {
            assert(flags.user == (specific_address.value < kernel.higher_half_direct_map.value));
            break :blk specific_address;
        } else {
            if (flags.user) {
                break :blk VirtualAddress.new(physical_region.address.value);
            } else {
                break :blk physical_region.address.to_higher_half_virtual_address();
            }
        }
    };

    // INFO: when allocating for userspace, virtual address spaces should be bootstrapped and not require this boolean value to be true
    if (flags.user) assert(!virtual_address_space.translate_address_extended(virtual_address, AlreadyLocked.yes).mapped);

    // Only map in user space
    if (flags.user) {
        try virtual_address_space.map_extended(physical_region.address, virtual_address, page_aligned_size, flags, AlreadyLocked.yes);
    }

    return Result{
        .physical_address = physical_region.address,
        .virtual_address = virtual_address,
    };
}

pub const MapError = error{
    already_present,
};

pub fn map(virtual_address_space: *VirtualAddressSpace, base_physical_address: PhysicalAddress, base_virtual_address: VirtualAddress, size: u64, flags: Flags) MapError!void {
    assert(kernel.memory_initialized);
    try map_extended(virtual_address_space, base_physical_address, base_virtual_address, size, flags, AlreadyLocked.no);
}

pub const AlreadyLocked = enum {
    no,
    yes,
};

pub fn map_extended(virtual_address_space: *VirtualAddressSpace, base_physical_address: PhysicalAddress, base_virtual_address: VirtualAddress, size: u64, flags: Flags, comptime already_locked: AlreadyLocked) MapError!void {
    if (already_locked == .yes) {
        assert(virtual_address_space.lock.status != 0);
    } else {
        virtual_address_space.lock.acquire();
    }
    defer {
        if (already_locked == .no) {
            virtual_address_space.lock.release();
        }
    }

    if (!is_aligned(size, arch.page_size)) {
        panic("Size {}, 0x{x} is not aligned to page size {}, 0x{x}", .{ size, size, arch.page_size, arch.page_size });
    }

    if (!kernel.memory_initialized) {
        @panic("Bootstrap VAS is still valid at the time of using map_extended");
    }

    log.debug("Mapping ({}, {}) to ({}, {}) - {}", .{ base_physical_address, base_physical_address.offset(size), base_virtual_address, base_virtual_address.offset(size), flags });

    // TODO: write good checks here
    //blk: {
    //const region = Region{
    //.address = base_virtual_address,
    //.size = size,
    //.flags = flags,
    //};

    //var recording_virtual_address_space = if (base_virtual_address.value >= kernel.higher_half_direct_map.value) &kernel.virtual_address_space else virtual_address_space;

    //for (recording_virtual_address_space.free_regions.items) |*free_region, free_region_i| {
    //if (free_region.contains(region)) {
    //log.debug("Contained", .{});
    //if (region.address.value == free_region.address.value) {
    //assert(free_region.size >= region.size);
    //if (free_region.size > region.size) {
    //free_region.address.value += region.size;
    //free_region.size -= region.size;
    //} else if (free_region.size == region.size) {
    //log.debug("deleting by swap remove", .{});
    //_ = recording_virtual_address_space.free_regions.swapRemove(free_region_i);
    //} else {
    //@panic("Container region is smaller than contained region");
    //}

    //recording_virtual_address_space.used_regions.append(kernel.virtual_address_space.heap.allocator, region) catch unreachable;
    //break :blk;
    //} else {
    //@panic("Wtf");
    //}
    //}
    //}

    //@panic("wtf no free space");
    //}

    var physical_address = base_physical_address;
    var virtual_address = base_virtual_address;
    const top_virtual_address = virtual_address.offset(size);

    while (virtual_address.value < top_virtual_address.value) : ({
        physical_address.value += arch.page_size;
        virtual_address.value += arch.page_size;
    }) {
        try VAS.map(virtual_address_space, physical_address, virtual_address, flags.to_arch_specific());
        if (kernel.config.safe_slow) {
            const translation_result = virtual_address_space.translate_address_extended(virtual_address, AlreadyLocked.yes);
            if (!translation_result.mapped) {
                @panic("address not present");
            }
            if (!translation_result.physical_address.is_valid()) {
                @panic("address not valid");
            }

            if (!translation_result.physical_address.is_equal(physical_address)) {
                @panic("address not equal");
            }
        }
    }
}

pub fn translate_address(virtual_address_space: *VirtualAddressSpace, virtual_address: VirtualAddress) ?PhysicalAddress {
    const result = translate_address_extended(virtual_address_space, virtual_address, AlreadyLocked.no);
    if (result.mapped) {
        return result.physical_address;
    } else {
        return null;
    }
}

pub const TranslationResult = struct {
    physical_address: PhysicalAddress,
    flags: Flags,
    page_size: u32,
    mapped: bool,
};

pub fn translate_address_extended(virtual_address_space: *VirtualAddressSpace, virtual_address: VirtualAddress, already_locked: AlreadyLocked) TranslationResult {
    if (already_locked == .yes) {
        assert(virtual_address_space.lock.status != 0);
    } else {
        virtual_address_space.lock.acquire();
    }
    defer {
        if (already_locked == .no) {
            virtual_address_space.lock.release();
        }
    }

    const result = VAS.translate_address(virtual_address_space, virtual_address);
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
        return common.zeroes(Flags);
    }

    pub inline fn to_arch_specific(flags: Flags) VAS.MemoryFlags {
        return VAS.new_flags(flags);
    }
};

pub fn add_used_region(virtual_address_space: *VirtualAddressSpace, region: Region) !void {
    if (region.is_valid_new_region_at_bootstrapping(virtual_address_space)) {
        try virtual_address_space.used_regions.append(kernel.virtual_address_space.heap.allocator.get_allocator(), region);
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
    size: u64,
    flags: Flags,

    pub fn is_valid_new_region_at_bootstrapping(region: Region, virtual_address_space: *VirtualAddressSpace) bool {
        const region_base = region.address.value;
        const region_top = region.get_top_address().value;

        for (virtual_address_space.used_regions.items) |used_region| {
            if (used_region.overlap(region_base, region_top)) {
                log.err("Overlap detected. Region: (0x{x}, 0x{x}). Used: (0x{x}, 0x{x})", .{ region_base, region_top, used_region.address.value, used_region.get_top_address().value });
                return false;
            }
        }

        for (virtual_address_space.free_regions.items) |free_region| {
            if (free_region.overlap(region_base, region_top)) {
                log.err("Overlap detected. Region: ({}, {}). Free: ({}, {})", .{ region_base, region_top, free_region.address.value, free_region.get_top_address() });
                return false;
            }
        }

        return true;
    }

    inline fn overlap(region: Region, region_base: u64, region_top: u64) bool {
        const other_base = region.address.value;
        const other_top = region.get_top_address().value;

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
        log.debug("(0x{x}, 0x{x}) contains (0x{x}, 0x{x})?", .{ container.address.value, container.get_top_address().value, contained.address.value, contained.get_top_address().value });
        if (container.get_top_address().value <= contained.address.value) {
            log.debug("contain1", .{});
            return false;
        }
        if (contained.get_top_address().value <= container.address.value) {
            log.debug("contain2", .{});
            return false;
        }
        if (container.address.value < contained.address.value) {
            @panic("foo1");
        } else if (container.address.value > contained.address.value) {
            @panic("foo2");
        } else {
            if (container.size < contained.size) @panic("Region overlap but it is too big");
            return true;
        }
    }

    inline fn get_top_address(virtual_memory_region: Region) VirtualAddress {
        return virtual_memory_region.address.offset(virtual_memory_region.size);
    }
};

pub fn map_reserved_region(virtual_address_space: *VirtualAddressSpace, physical_address: PhysicalAddress, virtual_address: VirtualAddress, size: u64, flags: Flags) void {
    assert(virtual_address_space == kernel.virtual_address_space);
    // Fake a free region
    virtual_address_space.free_regions.append(virtual_address_space.heap.allocator.get_allocator(), VirtualAddressSpace.Region{
        .address = virtual_address,
        .size = size,
        .flags = flags,
    }) catch unreachable;
    kernel.virtual_address_space.map(physical_address, virtual_address, size, flags) catch @panic("Unable to map reserved region");
}

pub fn format(virtual_address_space: VirtualAddressSpace, comptime _: []const u8, _: common.InternalFormatOptions, writer: anytype) @TypeOf(writer).Error!void {
    try common.internal_format(writer, "VirtualAddressSpace: ( .arch = {}, .privilege_level: {s}, .spinlock = {} )", .{ virtual_address_space.arch, @tagName(virtual_address_space.privilege_level), virtual_address_space.lock });
}

pub const Buffer = common.List.BufferList(VirtualAddressSpace, 64);

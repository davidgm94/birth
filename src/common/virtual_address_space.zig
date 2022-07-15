const VirtualAddressSpace = @This();

const root = @import("root");
const common = @import("../common.zig");
const context = @import("context");
const Allocator = common.Allocator;
const TODO = common.TODO;
const log = common.log.scoped(.VirtualAddressSpace);

const arch = common.arch;
const VirtualAddress = common.VirtualAddress;
const VirtualMemoryRegion = common.VirtualMemoryRegion;
const PhysicalMemoryRegion = common.PhysicalMemoryRegion;
const PhysicalAddress = common.PhysicalAddress;
const PhysicalAddressSpace = common.PhysicalAddressSpace;
const Heap = common.Heap;
const Spinlock = common.arch.Spinlock;

arch: arch.VirtualAddressSpace,
privilege_level: common.PrivilegeLevel,
heap: Heap,
lock: Spinlock,
initialized: bool,

/// This is going to return an identitty-mapped virtual address pointer and it is only intended to use for the
/// kernel address space
pub fn initialize_kernel_address_space(virtual_address_space: *VirtualAddressSpace, physical_address_space: *PhysicalAddressSpace) ?void {
    // TODO: defer memory free when this produces an error
    const arch_virtual_space = arch.VirtualAddressSpace.new(physical_address_space) orelse return null;
    // TODO: Maybe consume just the necessary space? We are doing this to avoid branches in the kernel heap allocator
    virtual_address_space.* = VirtualAddressSpace{
        .arch = arch_virtual_space,
        .privilege_level = .kernel,
        .heap = Heap.new(virtual_address_space),
        .lock = Spinlock.new(),
        .initialized = false,
    };

    log.debug("heap lock status after VAS creation: 0x{x}", .{virtual_address_space.heap.lock.status});
}

pub fn bootstrapping() VirtualAddressSpace {
    const bootstrap_arch_specific_vas = arch.VirtualAddressSpace.bootstrapping();
    return VirtualAddressSpace{
        .arch = bootstrap_arch_specific_vas,
        .privilege_level = .kernel,
        .heap = undefined,
        .lock = Spinlock.new(),
        .initialized = false,
    };
}

pub fn initialize_user_address_space(virtual_address_space: *VirtualAddressSpace, physical_address_space: *PhysicalAddressSpace, kernel_address_space: *VirtualAddressSpace) ?void {
    // TODO: defer memory free when this produces an error
    const arch_virtual_space = arch.VirtualAddressSpace.new(physical_address_space) orelse return null;
    // TODO: Maybe consume just the necessary space? We are doing this to avoid branches in the kernel heap allocator
    virtual_address_space.* = VirtualAddressSpace{
        .arch = arch_virtual_space,
        .privilege_level = .user,
        .heap = Heap.new(virtual_address_space),
        .lock = Spinlock.new(),
        .initialized = false,
    };

    virtual_address_space.arch.map_kernel_address_space_higher_half(kernel_address_space);
}

pub fn copy(old: *VirtualAddressSpace, new: *VirtualAddressSpace) void {
    new.* = old.*;
    new.heap.allocator.ptr = new;
}

fn acquire_lock(virtual_address_space: *VirtualAddressSpace) void {
    log.debug("State before acquiring VAS lock: {}", .{virtual_address_space.lock.status});
    virtual_address_space.lock.acquire();
    log.debug("State after acquiring VAS lock: {}", .{virtual_address_space.lock.status});
}

fn release_lock(virtual_address_space: *VirtualAddressSpace) void {
    log.debug("State before releasing VAS lock: {}", .{virtual_address_space.lock.status});
    virtual_address_space.lock.release();
    log.debug("State after releasing VAS lock: {}", .{virtual_address_space.lock.status});
}

pub fn allocate(virtual_address_space: *VirtualAddressSpace, byte_count: u64, maybe_specific_address: ?VirtualAddress, flags: Flags) !VirtualAddress {
    virtual_address_space.acquire_lock();
    defer virtual_address_space.release_lock();
    const page_count = common.bytes_to_pages(byte_count, context.page_size, .must_be_exact);
    log.debug("asking ph", .{});
    const physical_address = root.physical_address_space.allocate(page_count) orelse return Allocator.Error.OutOfMemory;
    log.debug("have ph", .{});

    const virtual_address = blk: {
        if (maybe_specific_address) |specific_address| {
            common.runtime_assert(@src(), !flags.user == specific_address.is_higher_half());
            break :blk specific_address;
        } else {
            if (flags.user) {
                break :blk VirtualAddress.new(physical_address.value);
            } else {
                break :blk physical_address.to_higher_half_virtual_address();
            }
        }
    };

    if (flags.user) common.runtime_assert(@src(), virtual_address_space.translate_address(virtual_address) == null);

    log.debug("Physical region: 0x{x}", .{physical_address.value});
    const physical_region = PhysicalMemoryRegion.new(physical_address, page_count * context.page_size);
    log.debug("After pr", .{});
    virtual_address_space.map_physical_region(physical_region, virtual_address, flags);
    log.debug("After map", .{});
    return virtual_address;
}

pub fn heap_create(virtual_address_space: *VirtualAddressSpace, comptime T: type) !*T {
    common.runtime_assert(@src(), @ptrToInt(virtual_address_space.heap.allocator.ptr) == @ptrToInt(virtual_address_space));
    return try virtual_address_space.heap.allocator.create(T);
}

pub fn heap_allocate(virtual_address_space: *VirtualAddressSpace, comptime T: type, count: u64) ![]T {
    common.runtime_assert(@src(), @ptrToInt(virtual_address_space.heap.allocator.ptr) == @ptrToInt(virtual_address_space));
    return try virtual_address_space.heap.allocator.alloc(T, count);
}

pub fn heap_allocate_bytes(virtual_address_space: *VirtualAddressSpace, size: u64, alignment: u29) ![]u8 {
    common.runtime_assert(@src(), @ptrToInt(virtual_address_space.heap.allocator.ptr) == @ptrToInt(virtual_address_space));
    return try virtual_address_space.heap.allocator.allocBytes(alignment, size, 0, 0);
}

pub fn map(virtual_address_space: *VirtualAddressSpace, physical_address: PhysicalAddress, virtual_address: VirtualAddress, flags: Flags) void {
    virtual_address_space.arch.map(physical_address, virtual_address, flags.to_arch_specific());
    const new_physical_address = virtual_address_space.translate_address(virtual_address) orelse @panic("address not present");
    common.runtime_assert(@src(), new_physical_address.is_valid());
    common.runtime_assert(@src(), new_physical_address.is_equal(physical_address));
}

pub fn translate_address(virtual_address_space: *VirtualAddressSpace, virtual_address: VirtualAddress) ?PhysicalAddress {
    return virtual_address_space.arch.translate_address(virtual_address);
}

pub fn make_current(virtual_address_space: *VirtualAddressSpace) void {
    virtual_address_space.arch.make_current();
}

// TODO: make this efficient
pub fn map_virtual_region(virtual_address_space: *VirtualAddressSpace, virtual_region: VirtualMemoryRegion, base_physical_address: PhysicalAddress, flags: Flags) void {
    var physical_address = base_physical_address;
    var virtual_address = virtual_region.address;
    const page_size = context.page_size;
    common.runtime_assert(@src(), common.is_aligned(physical_address.value, page_size));
    common.runtime_assert(@src(), common.is_aligned(virtual_address.value, page_size));
    common.runtime_assert(@src(), common.is_aligned(virtual_region.size, page_size));

    var size: u64 = 0;

    while (size < virtual_region.size) : (size += page_size) {
        virtual_address_space.map(physical_address, virtual_address, flags);
        physical_address.value += page_size;
        virtual_address.value += page_size;
    }
}

pub fn map_physical_region(virtual_address_space: *VirtualAddressSpace, physical_region: PhysicalMemoryRegion, base_virtual_address: VirtualAddress, flags: Flags) void {
    var physical_address = physical_region.address;
    var virtual_address = base_virtual_address;
    const page_size = context.page_size;
    common.runtime_assert(@src(), common.is_aligned(physical_address.value, page_size));
    common.runtime_assert(@src(), common.is_aligned(virtual_address.value, page_size));
    common.runtime_assert(@src(), common.is_aligned(physical_region.size, page_size));

    var size: u64 = 0;
    log.debug("Init mapping", .{});

    while (size < physical_region.size) : (size += page_size) {
        virtual_address_space.map(physical_address, virtual_address, flags);
        physical_address.value += page_size;
        virtual_address.value += page_size;
    }
    log.debug("End mapping", .{});
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

    pub inline fn to_arch_specific(flags: Flags) arch.VirtualAddressSpace.Flags {
        return arch.VirtualAddressSpace.new_flags(flags);
    }
};

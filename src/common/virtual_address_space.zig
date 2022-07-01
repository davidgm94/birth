const VirtualAddressSpace = @This();

const common = @import("../common.zig");
const TODO = common.TODO;
const Allocator = common.Allocator;
const log = common.log.scoped(.VirtualAddressSpace);

const arch = common.arch;
const VirtualAddress = common.VirtualAddress;
const VirtualMemoryRegion = common.VirtualMemoryRegion;
const PhysicalMemoryRegion = common.PhysicalMemoryRegion;
const PhysicalAddress = common.PhysicalAddress;
const PhysicalAddressSpace = common.PhysicalAddressSpace;

arch: arch.VirtualAddressSpace,
physical_address_space: *PhysicalAddressSpace,
allocator: Allocator,
initialized: bool,

pub fn new(heap_allocator: Allocator, physical_address_space: *PhysicalAddressSpace, cpu_features: common.arch.CPUFeatures) ?*VirtualAddressSpace {
    // TODO: defer memory free when this produces an error
    const arch_virtual_space = arch.VirtualAddressSpace.new(physical_address_space, cpu_features) orelse return null;
    const virtual_address_space = heap_allocator.create(VirtualAddressSpace) catch return null;
    virtual_address_space.* = VirtualAddressSpace{
        .arch = arch_virtual_space,
        .allocator = .{
            .ptr = virtual_address_space,
            .vtable = &allocator_interface.vtable,
        },
        .physical_address_space = physical_address_space,
        .initialized = false,
    };

    return virtual_address_space;
}

pub fn bootstrapping(cpu_features: common.arch.CPUFeatures) ?VirtualAddressSpace {
    const bootstrap_arch_specific_vas = arch.VirtualAddressSpace.bootstrapping(cpu_features);
    return VirtualAddressSpace{
        .arch = bootstrap_arch_specific_vas,
        .allocator = undefined,
        .initialized = false,
        .physical_address_space = undefined,
    };
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
pub fn map_virtual_region(virtual_address_space: *VirtualAddressSpace, virtual_region: VirtualMemoryRegion, base_physical_address: PhysicalAddress, flags: Flags, page_size: u64) void {
    var physical_address = base_physical_address;
    var virtual_address = virtual_region.address;
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

pub fn map_physical_region(virtual_address_space: *VirtualAddressSpace, physical_region: PhysicalMemoryRegion, base_virtual_address: VirtualAddress, flags: Flags, page_size: u64) void {
    var physical_address = physical_region.address;
    var virtual_address = base_virtual_address;
    common.runtime_assert(@src(), common.is_aligned(physical_address.value, page_size));
    common.runtime_assert(@src(), common.is_aligned(virtual_address.value, page_size));
    common.runtime_assert(@src(), common.is_aligned(physical_region.size, page_size));

    var size: u64 = 0;

    while (size < physical_region.size) : (size += page_size) {
        virtual_address_space.map(physical_address, virtual_address, flags);
        physical_address.value += page_size;
        virtual_address.value += page_size;
    }
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

var allocator_interface = struct {
    vtable: Allocator.VTable = .{
        .alloc = @ptrCast(fn alloc(virtual_address_space: *anyopaque, len: usize, ptr_align: u29, len_align: u29, return_address: usize) Allocator.Error![]u8, alloc),
        .resize = @ptrCast(fn resize(virtual_address_space: *anyopaque, old_mem: []u8, old_align: u29, new_size: usize, len_align: u29, return_address: usize) ?usize, resize),
        .free = @ptrCast(fn free(virtual_address_space: *anyopaque, old_mem: []u8, old_align: u29, return_address: usize) void, free),
    },

    // TODO: manage virtual memory
    fn alloc(virtual_address_space: *VirtualAddressSpace, size: usize, ptr_align: u29, len_align: u29, return_address: usize) Allocator.Error![]u8 {
        // TODO: use these parameters
        _ = return_address;
        _ = len_align;
        _ = ptr_align;
        const page_count = common.bytes_to_pages(size, virtual_address_space.physical_address_space.page_size, .must_be_exact);
        const physical_address = virtual_address_space.physical_address_space.allocate(page_count) orelse return Allocator.Error.OutOfMemory;
        return physical_address.access_kernel([*]u8)[0..size];
    }

    fn resize(virtual_address_space: *VirtualAddressSpace, old_mem: []u8, old_align: u29, new_size: usize, len_align: u29, return_address: usize) ?usize {
        _ = virtual_address_space;
        _ = old_mem;
        _ = old_align;
        _ = new_size;
        _ = len_align;
        _ = return_address;
        TODO(@src());
    }

    fn free(virtual_address_space: *VirtualAddressSpace, old_mem: []u8, old_align: u29, return_address: usize) void {
        _ = virtual_address_space;
        _ = old_mem;
        _ = old_align;
        _ = return_address;
        TODO(@src());
    }
}{};

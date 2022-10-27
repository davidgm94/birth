const PhysicalMemoryRegion = @This();

const common = @import("common");
const assert = common.assert;

const privileged = @import("privileged");
const PhysicalAddress = privileged.PhysicalAddress;
const VirtualAddress = privileged.VirtualAddress;
const VirtualMemoryRegion = privileged.VirtualMemoryRegion;

address: PhysicalAddress,
size: u64,

pub fn to_higher_half_virtual_address(physical_memory_region: PhysicalMemoryRegion) VirtualMemoryRegion {
    return VirtualMemoryRegion{
        .address = physical_memory_region.address.to_higher_half_virtual_address(),
        .size = physical_memory_region.size,
    };
}

pub fn to_identity_mapped_virtual_address(physical_memory_region: PhysicalMemoryRegion) VirtualMemoryRegion {
    return VirtualMemoryRegion{
        .address = VirtualAddress.new(physical_memory_region.address.value),
        .size = physical_memory_region.size,
    };
}

pub fn offset(physical_memory_region: PhysicalMemoryRegion, asked_offset: u64) PhysicalMemoryRegion {
    assert(asked_offset < physical_memory_region.size);

    var result = physical_memory_region;
    result.address = result.address.offset(asked_offset);
    result.size -= asked_offset;
    return result;
}

pub fn take_slice(physical_memory_region: PhysicalMemoryRegion, size: u64) PhysicalMemoryRegion {
    assert(size < physical_memory_region.size);

    var result = physical_memory_region;
    result.size = size;
    return result;
}

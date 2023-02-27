const lib = @import("lib");
const Allocator = lib.Allocator;
const assert = lib.assert;

const privileged = @import("privileged");
const riscv64 = privileged.arch.riscv64;
comptime {
    assert(riscv64 == privileged.arch.current);
}

const PhysicalAddress = privileged.arch.PhysicalAddress;
const PhysicalMemoryRegion = privileged.arch.PhysicalMemoryRegion;
const VirtualAddress = privileged.arch.VirtualAddress;
const VirtualAddressSpace = privileged.arch.VirtualAddressSpace;

pub const Specific = extern struct {
    foo: u64 = 0,
};

pub const needed_physical_memory_for_bootstrapping_cpu_driver_address_space = 0;

pub fn map(virtual_address_space: *VirtualAddressSpace, comptime locality: privileged.CoreLocality, asked_physical_address: PhysicalAddress(locality), asked_virtual_address: VirtualAddress(locality), size: u64, general_flags: VirtualAddressSpace.Flags, physical_allocator: *Allocator) !void {
    _ = physical_allocator;
    _ = general_flags;
    _ = size;
    _ = asked_virtual_address;
    _ = asked_physical_address;
    _ = virtual_address_space;
    @panic("TODO map");
    // // TODO: use flags
    // const flags = general_flags.toArchitectureSpecific(locality);
    // const vas_cr3 = virtual_address_space.arch.cr3;
    //
    // //log.debug("Mapping 0x{x}-0x{x} to 0x{x}-0x{x}", .{ asked_physical_address.value(), asked_physical_address.offset(size).value(), asked_virtual_address.value(), asked_virtual_address.offset(size).value() });
    //
    // // if (!asked_physical_address.isValid()) return Error.invalid_physical;
    // // if (!asked_virtual_address.isValid()) return Error.invalid_virtual;
    // if (size == 0) {
    //     return Error.invalid_size;
    // }
    //
    // if (!isAlignedGeneric(u64, asked_physical_address.value(), valid_page_sizes[0])) {
    //     return Error.unaligned_physical;
    // }
    //
    // if (!isAlignedGeneric(u64, asked_virtual_address.value(), valid_page_sizes[0])) {
    //     return Error.unaligned_virtual;
    // }
    //
    // if (!isAlignedGeneric(u64, size, valid_page_sizes[0])) {
    //     return Error.unaligned_size;
    // }
    //
    // if (asked_physical_address.value() >= lib.config.cpu_driver_higher_half_address) {
    //     return Error.invalid_physical;
    // }
    //
    // try map_function(vas_cr3, asked_physical_address.value(), asked_virtual_address.value(), size, flags, physical_allocator);
}

pub fn initKernelBSP(physical_memory_region: PhysicalMemoryRegion(.local)) VirtualAddressSpace {
    _ = physical_memory_region;
    @panic("TODO initKernelBSP");
}

pub fn makeCurrent(virtual_address_space: *const VirtualAddressSpace) void {
    _ = virtual_address_space;
    @panic("TODO makeCurrent");
}

const RNU = @import("RNU");
const ELF = RNU.ELF;
const PhysicalAddress = RNU.PhysicalAddress;
const VirtualAddress = RNU.VirtualAddress;
const VirtualMemoryRegion = RNU.VirtualMemoryRegion;
const VirtualAddressSpace = RNU.VirtualAddressSpace;

const kernel = @import("kernel");

pub const DetectError = error{
    unrecognized_format,
    not_implemented,
};

pub const Format = enum(u8) {
    ELF = 0,
    X = 1,

    pub fn detect(executable_file: []const u8) DetectError!Format {
        if (ELF.is_elf(executable_file)) {
            return Format.ELF;
        }

        return DetectError.unrecognized_format;
    }
};

pub fn load_into_kernel_memory(file: []const u8, format: Format) !InKernelMemory {
    const result = try switch (format) {
        .ELF => ELF.load_into_kernel_memory(file),
        else => unreachable,
    };

    return result;
}

pub fn load_into_user_memory(virtual_address_space: *VirtualAddressSpace, executable: InKernelMemory) !u64 {
    for (executable.sections[0..executable.section_count]) |section| {
        const physical_address = PhysicalAddress.new(section.kernel_address.value - kernel.higher_half_direct_map.value);
        const virtual_address = section.user_address;
        const size = section.size;
        const flags = section.flags;
        try virtual_address_space.map(physical_address, virtual_address, size, flags);
    }

    return executable.entry_point;
}

pub const max_sections = 32;

pub const InKernelMemory = struct {
    entry_point: u64,

    sections: [32]Section = undefined,
    section_count: u64 = 0,
};

pub const Section = struct {
    user_address: VirtualAddress,
    kernel_address: VirtualAddress,
    size: u64,
    flags: VirtualAddressSpace.Flags,
};

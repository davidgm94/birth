const lib = @import("lib");
const Allocator = lib.Allocator;
const log = lib.log.scoped(.Executable);
const privileged = @import("privileged");
const ELF = privileged.ELF;
const PhysicalAddress = privileged.PhysicalAddress;
const PhysicalAddressSpace = privileged.PhysicalAddressSpace;
const VirtualAddress = privileged.VirtualAddress;
const VirtualMemoryRegion = privileged.VirtualMemoryRegion;
const VirtualAddressSpace = privileged.VirtualAddressSpace;

pub const DetectError = error{
    unrecognized_format,
    not_implemented,
};

pub const Format = enum(u8) {
    ELF = 0,
    X = 1,

    pub fn detect(executable_file: []const u8) DetectError!Format {
        if (ELF.is_valid(executable_file)) {
            return Format.ELF;
        }

        return DetectError.unrecognized_format;
    }
};

pub fn load_into_kernel_memory(physical_address_space: *PhysicalAddressSpace, file: []const u8) !InKernelMemory {
    const result = try switch (try Format.detect(file)) {
        .ELF => ELF.load_into_kernel_memory(physical_address_space, file),
        else => unreachable,
    };

    return result;
}

pub const max_sections = 32;

pub const InKernelMemory = struct {
    entry_point: u64,

    sections: [32]Section = undefined,
    section_count: u64 = 0,

    pub fn load_into_user_memory(executable: InKernelMemory, physical_allocator: *Allocator) !u64 {
        log.debug("Assuming user memory right now...", .{});
        for (executable.sections[0..executable.section_count]) |section| {
            const physical_address = section.kernel_address.to_physical_address();
            const virtual_address = section.user_address;
            const size = section.size;
            const flags = section.flags;

            try privileged.arch.paging.map_current(physical_address.value(), virtual_address.value(), size, flags, physical_allocator);
        }

        return executable.entry_point;
    }
};

pub const Section = struct {
    user_address: VirtualAddress(.local),
    kernel_address: VirtualAddress(.local),
    size: usize,
    flags: VirtualAddressSpace.Flags,
};

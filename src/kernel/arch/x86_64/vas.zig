const common = @import("common");
const assert = common.assert;
const copy = common.copy;
const CustomAllocator = common.CustomAllocator;
const enum_count = common.enum_count;
const is_aligned = common.is_aligned;
const log = common.log.scoped(.VAS);
const zeroes = common.zeroes;
const zero_slice = common.zero_slice;

const privileged = @import("privileged");
const Heap = privileged.Heap;
const panic = privileged.panic;
const PhysicalAddress = privileged.PhysicalAddress;
const PhysicalAddressSpace = privileged.PhysicalAddressSpace;
const PhysicalMemoryRegion = privileged.PhysicalMemoryRegion;
const VirtualAddress = privileged.VirtualAddress;
const VirtualAddressSpace = privileged.VirtualAddressSpace;
const TranslationResult = VirtualAddressSpace.TranslationResult;

const arch = @import("arch");
const x86_64 = arch.x86_64;
const cr3 = x86_64.registers.cr3;

const higher_half_entry_index = 512 / 2;

pub const Specific = struct {
    cr3: cr3 = undefined,

    pub fn format(specific: Specific, comptime _: []const u8, _: common.InternalFormatOptions, writer: anytype) @TypeOf(writer).Error!void {
        try common.internal_format(writer, "{}", .{specific.cr3});
    }
};

const Indices = [enum_count(PageIndex)]u16;

const limine_physical_allocator = CustomAllocator{};

pub fn map_function(virtual_address_space: *VirtualAddressSpace, asked_physical_address: PhysicalAddress, asked_virtual_address: VirtualAddress, size: u64, flags: MemoryFlags, physical_allocator: *CustomAllocator) !void {
    if (size == arch.valid_page_sizes[0]) {
        try map_4k_page(virtual_address_space, asked_physical_address, asked_virtual_address, flags, physical_allocator);
    } else {
        const top_virtual_address = asked_virtual_address.offset(size);

        inline for (arch.reverse_valid_page_sizes) |reverse_page_size, reverse_page_index| {
            if (size >= reverse_page_size) {
                log.debug("Trying to map with page size 0x{x}", .{reverse_page_size});

                const is_smallest_page_size = reverse_page_index == arch.reverse_valid_page_sizes.len - 1;

                if (is_smallest_page_size) {
                    var virtual_address = asked_virtual_address;
                    var physical_address = asked_physical_address;

                    while (virtual_address.value < top_virtual_address.value) : ({
                        physical_address.value += reverse_page_size;
                        virtual_address.value += reverse_page_size;
                    }) {
                        try map_4k_page(virtual_address_space, physical_address, virtual_address, flags, physical_allocator);
                    }

                    break;
                } else {
                    const aligned_page_address = common.align_forward(asked_virtual_address.value, reverse_page_size);
                    const prologue_misalignment = aligned_page_address - asked_virtual_address.value;
                    const aligned_size_left = size - prologue_misalignment;

                    if (aligned_size_left >= reverse_page_size) {
                        if (prologue_misalignment != 0) {
                            log.debug("There is prologue misalignment: 0x{x}", .{prologue_misalignment});
                            try map_function(virtual_address_space, asked_physical_address, asked_virtual_address, prologue_misalignment, flags, physical_allocator);
                        }

                        const virtual_address = VirtualAddress.new(aligned_page_address);
                        const physical_address = asked_physical_address.offset(prologue_misalignment);
                        log.debug("Asked: {}. Aligned: {}", .{ asked_physical_address, physical_address });
                        const this_page_top_physical_address = physical_address.offset(aligned_size_left).aligned_backward(reverse_page_size);
                        const this_page_top_virtual_address = virtual_address.offset(aligned_size_left).aligned_backward(reverse_page_size);
                        const this_huge_page_size = this_page_top_virtual_address.value - virtual_address.value;
                        try map_generic(virtual_address_space, physical_address, virtual_address, this_huge_page_size, reverse_page_size, flags, physical_allocator);

                        const epilogue_misalignment = top_virtual_address.value - this_page_top_virtual_address.value;

                        if (epilogue_misalignment != 0) {
                            log.debug("There is epilogue misalignment: 0x{x}", .{epilogue_misalignment});
                            const epilogue_physical_address = this_page_top_physical_address;
                            const epilogue_virtual_address = this_page_top_virtual_address;

                            try map_function(virtual_address_space, epilogue_physical_address, epilogue_virtual_address, epilogue_misalignment, flags, physical_allocator);
                        }

                        break;
                    } else {
                        try map_generic(virtual_address_space, asked_physical_address, asked_virtual_address, size, arch.reverse_valid_page_sizes[reverse_page_index + 1], flags, physical_allocator);
                        @panic("else taken");
                    }
                }
            }
        }
    }
}

pub fn bootstrap_map(virtual_address_space: *VirtualAddressSpace, asked_physical_address: PhysicalAddress, asked_virtual_address: VirtualAddress, size: u64, general_flags: VirtualAddressSpace.Flags, physical_allocator: *CustomAllocator) !void {
    // TODO: use flags
    const flags = general_flags.to_arch_specific();

    if (common.config.safe_slow) {
        assert(size > 0);
        assert(asked_virtual_address.is_valid());
        assert(asked_physical_address.is_valid());
        assert(is_aligned(asked_virtual_address.value, arch.valid_page_sizes[0]));
        assert(is_aligned(asked_physical_address.value, arch.valid_page_sizes[0]));
    }

    log.debug("Trying to map 0x{x} bytes from {} to {}", .{ size, asked_physical_address, asked_virtual_address });
    try map_function(virtual_address_space, asked_physical_address, asked_virtual_address, size, flags, physical_allocator);
}

fn map_generic(virtual_address_space: *VirtualAddressSpace, asked_physical_address: PhysicalAddress, asked_virtual_address: VirtualAddress, size: u64, comptime asked_page_size: comptime_int, flags: MemoryFlags, physical_allocator: *CustomAllocator) !void {
    log.debug("Map generic page size: 0x{x}. From {} to {}", .{ asked_page_size, asked_physical_address, asked_virtual_address });
    const reverse_index = switch (asked_page_size) {
        arch.reverse_valid_page_sizes[0] => 0,
        arch.reverse_valid_page_sizes[1] => 1,
        arch.reverse_valid_page_sizes[2] => 2,
        else => @compileError("Invalid page size"),
    };
    _ = reverse_index;

    if (true) {
        if (!common.is_aligned(asked_physical_address.value, asked_page_size)) {
            log.debug("PA: {}. Page size: 0x{x}", .{ asked_physical_address, asked_page_size });
            @panic("wtf 1");
        }
        if (!common.is_aligned(asked_virtual_address.value, asked_page_size)) {
            @panic("wtf 2");
        }
        if (!common.is_aligned(size, asked_page_size)) {
            log.debug("Asked size: 0x{x}. Asked page size: 0x{x}", .{ size, asked_page_size });
            @panic("wtf 3");
        }
    } else {
        assert(common.is_aligned(asked_physical_address.value, asked_page_size));
        assert(common.is_aligned(asked_virtual_address.value, asked_page_size));
        assert(common.is_aligned(size, asked_page_size));
    }

    var virtual_address = asked_virtual_address;
    var physical_address = asked_physical_address;
    const top_virtual_address = asked_virtual_address.offset(size);

    // TODO: batch better
    switch (asked_page_size) {
        // 1 GB
        0x1000 * 0x200 * 0x200 => {
            while (virtual_address.value < top_virtual_address.value) : ({
                physical_address.value += asked_page_size;
                virtual_address.value += asked_page_size;
            }) {
                try map_1gb_page(virtual_address_space, physical_address, virtual_address, flags, physical_allocator);
            }
        },
        // 2 MB
        0x1000 * 0x200 => {
            while (virtual_address.value < top_virtual_address.value) : ({
                physical_address.value += asked_page_size;
                virtual_address.value += asked_page_size;
            }) {
                try map_2mb_page(virtual_address_space, physical_address, virtual_address, flags, physical_allocator);
            }
        },
        // Smallest: 4 KB
        0x1000 => {
            while (virtual_address.value < top_virtual_address.value) : ({
                physical_address.value += asked_page_size;
                virtual_address.value += asked_page_size;
            }) {
                try map_4k_page(virtual_address_space, physical_address, virtual_address, flags, physical_allocator);
            }
        },
        else => @compileError("Invalid reverse valid page size"),
    }
}

fn map_1gb_page(virtual_address_space: *VirtualAddressSpace, physical_address: PhysicalAddress, virtual_address: VirtualAddress, flags: MemoryFlags, physical_allocator: *CustomAllocator) !void {
    const indices = compute_indices(virtual_address);

    const pml4_table = get_pml4_table(virtual_address_space.arch.cr3);
    const pdp_table = get_pdp_table(pml4_table, indices, physical_allocator);

    try page_tables_map_1_gb_page(pdp_table, indices, physical_address, flags);

    if (common.config.safe_slow) {
        const translated_address = virtual_address_space.translate_address(virtual_address) orelse @panic("WTFASD");
        if (translated_address.value != physical_address.value) @panic("WTF seriously");
    }
}

fn map_2mb_page(virtual_address_space: *VirtualAddressSpace, physical_address: PhysicalAddress, virtual_address: VirtualAddress, flags: MemoryFlags, physical_allocator: *CustomAllocator) !void {
    const indices = compute_indices(virtual_address);

    const pml4_table = get_pml4_table(virtual_address_space.arch.cr3);
    const pdp_table = get_pdp_table(pml4_table, indices, physical_allocator);
    const pd_table = get_pd_table(pdp_table, indices, physical_allocator);

    try page_tables_map_2_mb_page(pd_table, indices, physical_address, flags);

    if (common.config.safe_slow) {
        const translated_address = virtual_address_space.translate_address(virtual_address) orelse @panic("WTFASD");
        if (translated_address.value != physical_address.value) @panic("WTF seriously");
    }
}

fn map_4k_page(virtual_address_space: *VirtualAddressSpace, physical_address: PhysicalAddress, virtual_address: VirtualAddress, flags: MemoryFlags, physical_allocator: *CustomAllocator) MapError!void {
    const indices = compute_indices(virtual_address);

    const pml4_table = get_pml4_table(virtual_address_space.arch.cr3);
    const pdp_table = get_pdp_table(pml4_table, indices, physical_allocator);
    const pd_table = get_pd_table(pdp_table, indices, physical_allocator);
    const p_table = get_p_table(pd_table, indices, physical_allocator);

    try page_tables_map_4_kb_page(p_table, indices, physical_address, flags);

    if (common.config.safe_slow) {
        const translated_address = virtual_address_space.translate_address(virtual_address) orelse @panic("WTFASD");
        if (translated_address.value != physical_address.value) @panic("WTF seriously");
    }
}

fn get_pml4_table(cr3_register: cr3) *volatile PML4Table {
    const pml4_physical_address = cr3_register.get_address();
    const pml4_virtual_address = switch (common.os) {
        .freestanding => pml4_physical_address.to_higher_half_virtual_address(),
        .uefi => pml4_physical_address.to_identity_mapped_virtual_address(),
        else => @compileError("OS not supported"),
    };

    if (common.config.safe_slow) {
        assert(pml4_virtual_address.is_valid());
    }

    return pml4_virtual_address.access(*volatile PML4Table);
}

fn get_pdp_table(pml4_table: *volatile PML4Table, indices: Indices, physical_allocator: *CustomAllocator) *volatile PDPTable {
    const entry_pointer = &pml4_table[indices[@enumToInt(PageIndex.PML4)]];

    const table_physical_address = physical_address_blk: {
        const entry_value = entry_pointer.*;
        if (entry_value.present) {
            break :physical_address_blk unpack_address(entry_value);
        } else {
            // TODO: track this physical allocation in order to map it later in the kernel address space
            const entry_allocation = physical_allocator.allocate_bytes(@sizeOf(PDPTable), arch.valid_page_sizes[0]) catch @panic("wtf");
            const entry_physical_region = PhysicalMemoryRegion{
                .address = PhysicalAddress.new(entry_allocation.address),
                .size = entry_allocation.size,
            };

            if (common.config.safe_slow) {
                for (entry_physical_region.address.to_higher_half_virtual_address().access([*]const u8)[0..entry_physical_region.size]) |byte| {
                    assert(byte == 0);
                }
            }

            entry_pointer.* = PML4TE{
                .present = true,
                .read_write = true,
                .address = pack_address(PML4TE, entry_physical_region.address),
            };

            break :physical_address_blk entry_physical_region.address;
        }
    };

    const table_virtual_address = switch (common.os) {
        .freestanding => table_physical_address.to_higher_half_virtual_address(),
        .uefi => table_physical_address.to_identity_mapped_virtual_address(),
        else => @compileError("OS not supported"),
    };

    const is_valid = table_virtual_address.is_valid();
    if (!is_valid) {
        log.debug("check pdp table valid: {}", .{is_valid});
    }

    if (common.config.safe_slow) assert(is_valid);

    return table_virtual_address.access(*volatile PDPTable);
}

const MapError = error{
    already_present,
};

fn get_page_entry(comptime Entry: type, physical_address: PhysicalAddress, flags: MemoryFlags) Entry {
    return Entry{
        .present = true,
        .read_write = flags.read_write,
        .user = flags.user,
        .page_level_cache_disable = flags.cache_disable,
        .global = flags.global,
        .pat = flags.pat,
        .address = pack_address(Entry, physical_address),
        .execute_disable = flags.execute_disable,
    };
}

fn page_tables_map_1_gb_page(pdp_table: *volatile PDPTable, indices: Indices, physical_address: PhysicalAddress, flags: MemoryFlags) MapError!void {
    const entry_pointer = &pdp_table[indices[@enumToInt(PageIndex.PDP)]];

    if (entry_pointer.present) return MapError.already_present;

    assert(common.is_aligned(physical_address.value, arch.valid_page_sizes[2]));

    entry_pointer.* = @bitCast(PDPTE, get_page_entry(PDPTE_1GB, physical_address, flags));
}

fn page_tables_map_2_mb_page(pd_table: *volatile PDTable, indices: Indices, physical_address: PhysicalAddress, flags: MemoryFlags) !void {
    const entry_pointer = &pd_table[indices[@enumToInt(PageIndex.PD)]];
    const entry_value = entry_pointer.*;

    if (entry_value.present) return MapError.already_present;

    assert(common.is_aligned(physical_address.value, arch.valid_page_sizes[1]));

    entry_pointer.* = @bitCast(PDTE, get_page_entry(PDTE_2MB, physical_address, flags));
}

fn page_tables_map_4_kb_page(p_table: *volatile PTable, indices: Indices, physical_address: PhysicalAddress, flags: MemoryFlags) !void {
    const entry_pointer = &p_table[indices[@enumToInt(PageIndex.PT)]];

    if (entry_pointer.present) return MapError.already_present;

    assert(common.is_aligned(physical_address.value, arch.valid_page_sizes[0]));

    entry_pointer.* = @bitCast(PTE, get_page_entry(PTE, physical_address, flags));
}

fn get_pd_table(pdp_table: *volatile PDPTable, indices: Indices, physical_allocator: *CustomAllocator) *volatile PDTable {
    const entry_pointer = &pdp_table[indices[@enumToInt(PageIndex.PDP)]];

    const table_physical_address = physical_address_blk: {
        const entry_value = entry_pointer.*;
        if (entry_value.present) {
            // The address is mapped with a 1GB page
            if (entry_value.page_size) {
                @panic("todo pd table page size");
            }
            break :physical_address_blk unpack_address(entry_value);
        } else {
            // TODO: track this physical allocation in order to map it later in the kernel address space
            const entry_allocation = physical_allocator.allocate_bytes(@sizeOf(PDTable), arch.valid_page_sizes[0]) catch @panic("wtf");
            const entry_physical_region = PhysicalMemoryRegion{
                .address = PhysicalAddress.new(entry_allocation.address),
                .size = entry_allocation.size,
            };

            if (common.config.safe_slow) {
                for (entry_physical_region.address.to_higher_half_virtual_address().access([*]const u8)[0..entry_physical_region.size]) |byte| {
                    assert(byte == 0);
                }
            }

            entry_pointer.* = PDPTE{
                .present = true,
                .read_write = true,
                .address = pack_address(PDPTE, entry_physical_region.address),
            };

            break :physical_address_blk entry_physical_region.address;
        }
    };

    const table_virtual_address = switch (common.os) {
        .freestanding => table_physical_address.to_higher_half_virtual_address(),
        .uefi => table_physical_address.to_identity_mapped_virtual_address(),
        else => @compileError("OS not supported"),
    };
    if (common.config.safe_slow) assert(table_virtual_address.is_valid());
    return table_virtual_address.access(*volatile PDTable);
}

fn get_p_table(pd_table: *volatile PDTable, indices: Indices, physical_allocator: *CustomAllocator) *volatile PTable {
    const entry_pointer = &pd_table[indices[@enumToInt(PageIndex.PD)]];

    const table_physical_address = physical_address_blk: {
        const entry_value = entry_pointer.*;
        if (entry_value.present) {
            // The address is mapped with a 2MB page
            if (entry_value.page_size) {
                @panic("todo ptable page size");
            }
            break :physical_address_blk unpack_address(entry_value);
        } else {
            const entry_allocation = physical_allocator.allocate_bytes(@sizeOf(PTable), arch.valid_page_sizes[0]) catch @panic("wtf");
            const entry_physical_region = PhysicalMemoryRegion{
                .address = PhysicalAddress.new(entry_allocation.address),
                .size = entry_allocation.size,
            };

            if (common.config.safe_slow) {
                for (entry_physical_region.address.to_higher_half_virtual_address().access([*]const u8)[0..entry_physical_region.size]) |byte| {
                    assert(byte == 0);
                }
            }

            entry_pointer.* = PDTE{
                .present = true,
                .read_write = true,
                .address = pack_address(PDTE, entry_physical_region.address),
            };

            break :physical_address_blk entry_physical_region.address;
        }
    };

    const table_virtual_address = switch (common.os) {
        .freestanding => table_physical_address.to_higher_half_virtual_address(),
        .uefi => table_physical_address.to_identity_mapped_virtual_address(),
        else => @compileError("OS not supported"),
    };

    if (common.config.safe_slow) assert(table_virtual_address.is_valid());

    return table_virtual_address.access(*volatile PTable);
}

const half_entry_count = (@sizeOf(PML4Table) / @sizeOf(PML4TE)) / 2;

pub const needed_physical_memory_for_bootstrapping_kernel_address_space = @sizeOf(PML4Table) + @sizeOf(PDPTable) * 256;

pub fn init_kernel_bsp(allocation_region: PhysicalMemoryRegion) VirtualAddressSpace {
    const pml4_physical_region = allocation_region.take_slice(@sizeOf(PML4Table));
    const pdp_physical_region = allocation_region.offset(@sizeOf(PML4Table));
    const pml4_entries = switch (common.os) {
        .freestanding => pml4_physical_region.to_higher_half_virtual_address().access(PML4TE),
        .uefi => pml4_physical_region.to_identity_mapped_virtual_address().access(PML4TE),
        else => @compileError("OS not supported"),
    };

    for (pml4_entries[0..half_entry_count]) |*entry| {
        entry.* = @bitCast(PML4TE, @as(u64, 0));
    }

    for (pml4_entries[half_entry_count..]) |*entry, i| {
        entry.* = PML4TE{
            .present = true,
            .read_write = true,
            .address = pack_address(PML4TE, pdp_physical_region.offset(i * @sizeOf(PDPTable)).address),
        };
    }

    return VirtualAddressSpace{
        .id = 0,
        .arch = .{
            .cr3 = cr3.from_address(pml4_physical_region.address),
        },
        .privileged = true,
        .owner = .kernel,
        .heap = Heap{},
    };
}

//pub fn init_user(virtual_address_space: *VirtualAddressSpace) void {
//if (common.os != .freestanding) @compileError("OS not supported"),

//const kernel = @import("kernel");

//if (common.config.safe_slow) assert(virtual_address_space.privilege_level == .user);
//const pml4_table_page_count = comptime @divExact(@sizeOf(PML4Table), arch.valid_page_sizes[0]);
//const pml4_physical_region = kernel.physical_address_space.allocate_pages(page_size, pml4_table_page_count, .{ .zeroed = true }) orelse @panic("wtf");
//virtual_address_space.arch = Specific{
//.cr3 = cr3.from_address(pml4_physical_region.address),
//};

//const pml4_virtual_address = pml4_physical_region.address.to_higher_half_virtual_address();
//const pml4 = pml4_virtual_address.access(*PML4Table);
//const lower_half_pml4 = pml4[0 .. pml4.len / 2];
//const higher_half_pml4 = pml4[0 .. pml4.len / 2];
//zero_slice(PML4Entry, lower_half_pml4);

//if (common.config.safe_slow) {
//assert(lower_half_pml4.len == half_entry_count);
//assert(higher_half_pml4.len == half_entry_count);
//}

//map_kernel_address_space_higher_half(virtual_address_space, kernel.virtual_address_space);
//}

const time_map = false;

const PanicPolicy = enum {
    panic,
    not_panic,
};

pub inline fn switch_address_spaces_if_necessary(new_address_space: *VirtualAddressSpace) void {
    const current_cr3 = cr3.read();
    if (@bitCast(u64, current_cr3) != @bitCast(u64, new_address_space.arch.cr3)) {
        new_address_space.arch.cr3.write();
    }
}

pub inline fn is_current(virtual_address_space: *VirtualAddressSpace) bool {
    const vas_cr3 = virtual_address_space.arch.cr3;
    const current_cr3 = cr3.read();
    return current_cr3.equal(vas_cr3);
}

pub fn from_current(owner: privileged.ResourceOwner) VirtualAddressSpace {
    return VirtualAddressSpace{
        .id = 0,
        .arch = Specific{
            .cr3 = cr3.read(),
        },
        .privileged = true,
        .owner = owner,
        .heap = .{},
    };
}

pub fn map_kernel_address_space_higher_half(virtual_address_space: *VirtualAddressSpace, kernel_address_space: *VirtualAddressSpace) void {
    const cr3_physical_address = virtual_address_space.arch.cr3.get_address();
    const cr3_virtual_address = cr3_physical_address.to_higher_half_virtual_address();
    // TODO: maybe user flag is not necessary?
    const pml4 = cr3_virtual_address.access(*PML4Table);
    zero_slice(PML4TE, pml4[0..0x100]);
    copy(PML4TE, pml4[0x100..], kernel_address_space.arch.cr3.get_address().to_higher_half_virtual_address().access(*PML4Table)[0x100..]);
    log.debug("USER CR3: 0x{x}", .{cr3_physical_address.value});
}

//pub fn translate_address(virtual_address_space: *VirtualAddressSpace, asked_virtual_address: VirtualAddress) TranslationResult {
//assert(asked_virtual_address.is_valid());
//if (!is_aligned(asked_virtual_address.value, x86_64.page_size)) {
//log.err("Virtual address {} not aligned", .{asked_virtual_address});
//return zeroes(TranslationResult);
//}

//const virtual_address = asked_virtual_address;
//const indices = compute_indices(virtual_address);

//const pml4_table = blk: {
//const pml4_physical_address = virtual_address_space.arch.cr3.get_address();
//const pml4_virtual_address = pml4_physical_address.to_higher_half_virtual_address();
//if (common.config.safe_slow) {
//assert(pml4_virtual_address.is_valid());
//}

//break :blk pml4_virtual_address.access(*volatile PML4Table);
//};

//const pdp_table = blk: {
//const pml4_entry = pml4_table[indices[@enumToInt(PageIndex.PML4)]];
//if (!pml4_entry.present) {
////log.err("Virtual address {} not present: PML4", .{virtual_address});
//return zeroes(TranslationResult);
//}

//const pdp_table_virtual_address = unpack_address(pml4_entry).to_higher_half_virtual_address();
//if (common.config.safe_slow) assert(pdp_table_virtual_address.is_valid());
//break :blk pdp_table_virtual_address.access(*volatile PDPTable);
//};

//const pd_table = blk: {
//const pdp_entry = pdp_table[indices[@enumToInt(PageIndex.PDP)]];
//if (!pdp_entry.present) {
////log.err("Virtual address {} not present: PDP", .{virtual_address});
//return zeroes(TranslationResult);
//}

//const physical_address = unpack_address(pdp_entry);
//// The address is mapped with a 1 GB page
//if (pdp_entry.page_size) {
//return TranslationResult{
//.physical_address = physical_address,
//.page_size = 1024 * 1024 * 1024,
//.mapped = true,
//.flags = .{
//.write = pdp_entry.read_write,
//.user = pdp_entry.user,
//.cache_disable = pdp_entry.page_level_cache_disable,
//.execute = !pdp_entry.execute_disable,
//},
//};
//}

//const pd_table_virtual_address = physical_address.to_higher_half_virtual_address();
//if (common.config.safe_slow) assert(pd_table_virtual_address.is_valid());
//break :blk pd_table_virtual_address.access(*volatile PDTable);
//};

//const p_table = blk: {
//const pd_entry = pd_table[indices[@enumToInt(PageIndex.PD)]];
//if (!pd_entry.present) {
////log.err("Virtual address {} not present: PD", .{virtual_address});
//return zeroes(TranslationResult);
//}

//const physical_address = unpack_address(pd_entry);
//// The address is mapped with a 2MB page
//if (pd_entry.page_size) {
//return TranslationResult{
//.physical_address = physical_address,
//.page_size = 2 * 1024 * 1024,
//.mapped = true,
//.flags = .{
//.write = pd_entry.read_write,
//.user = pd_entry.user,
//.cache_disable = pd_entry.page_level_cache_disable,
//.execute = !pd_entry.execute_disable,
//},
//};
//}

//const p_table_virtual_address = physical_address.to_higher_half_virtual_address();
//if (common.config.safe_slow) assert(p_table_virtual_address.is_valid());
//break :blk p_table_virtual_address.access(*volatile PDTable);
//};

//const p_entry = p_table[indices[@enumToInt(PageIndex.PT)]];
//if (!p_entry.present) {
//return zeroes(TranslationResult);
//}

//const physical_address = unpack_address(p_entry);
//return TranslationResult{
//.physical_address = physical_address,
//.page_size = 0x1000,
//.mapped = true,
//.flags = .{
//.write = p_entry.read_write,
//.user = p_entry.user,
//.cache_disable = p_entry.page_level_cache_disable,
//.execute = !p_entry.execute_disable,
//},
//};
//}

fn compute_indices(virtual_address: VirtualAddress) Indices {
    var indices: Indices = undefined;
    var va = virtual_address.value;
    va = va >> 12;
    indices[3] = @truncate(u9, va);
    va = va >> 9;
    indices[2] = @truncate(u9, va);
    va = va >> 9;
    indices[1] = @truncate(u9, va);
    va = va >> 9;
    indices[0] = @truncate(u9, va);

    return indices;
}

pub fn make_current(virtual_address_space: *VirtualAddressSpace) void {
    if (common.config.safe_slow) {
        //if (virtual_address_space == &kernel.virtual_address_space) {
        //log.debug("About to switch to kernel address space", .{});
        //const instruction_pointer = VirtualAddress.new(@returnAddress()).aligned_backward(page_size);
        //const frame_pointer = VirtualAddress.new(@frameAddress()).aligned_backward(page_size);
        //const global_ptr_va = VirtualAddress.new(@ptrToInt(&kernel.virtual_address_space)).aligned_backward(page_size);

        //const instruction_pointer_physical_address = kernel.bootloader_virtual_address_space.translate_address(instruction_pointer) orelse unreachable;
        //const frame_pointer_physical_address = kernel.bootloader_virtual_address_space.translate_address(frame_pointer) orelse unreachable;
        //const global_pointer_physical_address = kernel.bootloader_virtual_address_space.translate_address(global_ptr_va) orelse unreachable;

        //log.debug("Checking if instruction pointer is mapped to {}...", .{instruction_pointer_physical_address});
        //assert(virtual_address_space.translate_address(instruction_pointer) != null);
        //log.debug("Checking if frame pointer is mapped to {}...", .{frame_pointer_physical_address});
        //assert(virtual_address_space.translate_address(frame_pointer) != null);
        //log.debug("Checking if a global variable is mapped to {}...", .{global_pointer_physical_address});
        //assert(virtual_address_space.translate_address(global_ptr_va) != null);

        //assert(virtual_address_space.translate_address(virtual_address_space.arch.cr3.get_address().to_higher_half_virtual_address()) != null);
        //}
    }

    log.debug("Writing CR3: 0x{x}", .{@bitCast(u64, virtual_address_space.arch.cr3)});
    virtual_address_space.arch.cr3.write();
}

pub inline fn new_flags(general_flags: VirtualAddressSpace.Flags) MemoryFlags {
    return MemoryFlags{
        .read_write = general_flags.write,
        .user = general_flags.user,
        .cache_disable = general_flags.cache_disable,
        .execute_disable = !general_flags.execute,
    };
}

// TODO:
pub const MemoryFlags = packed struct(u64) {
    present: bool = true,
    read_write: bool = false,
    user: bool = false,
    write_through: bool = false,
    cache_disable: bool = false,
    dirty: bool = false,
    global: bool = false,
    pat: bool = false,
    reserved: u55 = 0,
    execute_disable: bool = false,

    comptime {
        assert(@sizeOf(u64) == @sizeOf(MemoryFlags));
    }
};

const address_mask: u64 = 0x0000_00ff_ffff_f000;

const PageIndex = enum(u3) {
    PML4 = 0,
    PDP = 1,
    PD = 2,
    PT = 3,
};

fn unpack_address(entry: anytype) PhysicalAddress {
    const T = @TypeOf(entry);
    const address_offset = @bitOffsetOf(T, "address");
    return PhysicalAddress.new(@as(u64, entry.address) << address_offset);
}

fn get_address_type(comptime T: type) type {
    var a: T = undefined;
    return @TypeOf(@field(a, "address"));
}

fn pack_address(comptime T: type, physical_address: PhysicalAddress) get_address_type(T) {
    const address_offset = @bitOffsetOf(T, "address");
    return @intCast(get_address_type(T), physical_address.value >> address_offset);
}

const PML4TE = packed struct(u64) {
    present: bool = false,
    read_write: bool = false,
    user: bool = false,
    page_level_write_through: bool = false,
    page_level_cache_disable: bool = false,
    accessed: bool = false,
    reserved0: u5 = 0,
    hlat_restart: bool = false,
    address: u28,
    reserved1: u23 = 0,
    execute_disable: bool = false,

    comptime {
        assert(@sizeOf(@This()) == @sizeOf(u64));
        assert(@bitSizeOf(@This()) == @bitSizeOf(u64));
    }
};

const PDPTE = packed struct(u64) {
    present: bool = false,
    read_write: bool = false,
    user: bool = false,
    page_level_write_through: bool = false,
    page_level_cache_disable: bool = false,
    accessed: bool = false,
    reserved0: u1 = 0,
    page_size: bool = false,
    reserved1: u3 = 0,
    hlat_restart: bool = false,
    address: u28,
    reserved2: u23 = 0,
    execute_disable: bool = false,

    comptime {
        assert(@sizeOf(@This()) == @sizeOf(u64));
        assert(@bitSizeOf(@This()) == @bitSizeOf(u64));
    }
};

const PDPTE_1GB = packed struct(u64) {
    present: bool = false,
    read_write: bool = false,
    user: bool = false,
    page_level_write_through: bool = false,
    page_level_cache_disable: bool = false,
    accessed: bool = false,
    dirty: bool = false,
    page_size: bool = true,
    global: bool = false,
    reserved: u2 = 0,
    hlat_restart: bool = false,
    pat: bool = false,
    address: u29,
    reserved2: u10 = 0,
    ignored: u7 = 0,
    protection_key: u4 = 0,
    execute_disable: bool = false,

    comptime {
        assert(@sizeOf(@This()) == @sizeOf(u64));
        assert(@bitSizeOf(@This()) == @bitSizeOf(u64));
    }
};

const PDTE = packed struct(u64) {
    present: bool = false,
    read_write: bool = false,
    user: bool = false,
    page_level_write_through: bool = false,
    page_level_cache_disable: bool = false,
    accessed: bool = false,
    reserved0: u1 = 0,
    page_size: bool = false,
    reserved1: u3 = 0,
    hlat_restart: bool = false,
    address: u28,
    reserved2: u23 = 0,
    execute_disable: bool = false,

    comptime {
        assert(@sizeOf(@This()) == @sizeOf(u64));
        assert(@bitSizeOf(@This()) == @bitSizeOf(u64));
    }
};

const PDTE_2MB = packed struct(u64) {
    present: bool = false,
    read_write: bool = false,
    user: bool = false,
    page_level_write_through: bool = false,
    page_level_cache_disable: bool = false,
    accessed: bool = false,
    dirty: bool = false,
    page_size: bool = true,
    global: bool = false,
    ignored: u2 = 0,
    hlat_restart: bool = false,
    pat: bool = false,
    reserved: u8 = 0,
    address: u21,
    reserved2: u10 = 0,
    ignored2: u7 = 0,
    protection_key: u4 = 0,
    execute_disable: bool = false,

    comptime {
        assert(@sizeOf(@This()) == @sizeOf(u64));
        assert(@bitSizeOf(@This()) == @bitSizeOf(u64));
    }
};

const PTE = packed struct(u64) {
    present: bool = false,
    read_write: bool = false,
    user: bool = false,
    page_level_write_through: bool = false,
    page_level_cache_disable: bool = false,
    accessed: bool = false,
    dirty: bool = false,
    pat: bool = false,
    global: bool = false,
    reserved1: u2 = 0,
    hlat_restart: bool = false,
    address: u28,
    reserved2: u23 = 0,
    execute_disable: bool = false,

    comptime {
        assert(@sizeOf(@This()) == @sizeOf(u64));
        assert(@bitSizeOf(@This()) == @bitSizeOf(u64));
    }
};

const PML4Table = [512]PML4TE;
const PDPTable = [512]PDPTE;
const PDTable = [512]PDTE;
const PTable = [512]PTE;

const lib = @import("lib");
const alignForward = lib.alignForward;
const alignForwardGeneric = lib.alignForwardGeneric;
const alignBackward = lib.alignBackward;
const alignBackwardGeneric = lib.alignBackwardGeneric;
const isAligned = lib.isAligned;
const isAlignedGeneric = lib.isAlignedGeneric;
const assert = lib.assert;
const copy = lib.copy;
const enumCount = lib.enumCount;
const log = lib.log.scoped(.VAS);
const zeroes = lib.zeroes;
const Allocator = lib.Allocator;

const privileged = @import("privileged");
const Heap = privileged.Heap;
const PageAllocator = privileged.PageAllocator;

const valid_page_sizes = lib.arch.x86_64.valid_page_sizes;
const reverse_valid_page_sizes = lib.arch.x86_64.reverse_valid_page_sizes;

const x86_64 = privileged.arch.x86_64;
const cr3 = x86_64.registers.cr3;
const PhysicalAddress = privileged.PhysicalAddress;
const VirtualAddress = privileged.VirtualAddress;
const PhysicalMemoryRegion = privileged.PhysicalMemoryRegion;
const VirtualMemoryRegion = privileged.VirtualMemoryRegion;
const PhysicalAddressSpace = privileged.PhysicalAddressSpace;
const Mapping = privileged.Mapping;

const bootloader = @import("bootloader");

const page_table_level_count = 4;

pub const CPUPageTables = extern struct {
    pml4_table: PhysicalAddress,
    pdp_table: PhysicalAddress,
    pd_table: PhysicalAddress,
    p_table: PhysicalAddress,

    const base = 0xffff_ffff_8000_0000;
    const top = base + pte_count * lib.arch.valid_page_sizes[0];
    const pte_count = page_table_entry_count - left_ptables;
    const left_ptables = 4;
    const pml4_index = 0x1ff;
    const pdp_index = 0x1fe;
    const pd_index = 0;
    const allocated_table_count =
        1 + // PML4
        1 + // PDP
        1 + // PD
        1; // PT
    const allocated_size = allocated_table_count * 0x1000;

    const page_table_base = top;

    comptime {
        assert(top + (left_ptables * lib.arch.valid_page_sizes[0]) == base + lib.arch.valid_page_sizes[1]);
    }

    pub fn initialize(page_allocator: PageAllocator) !CPUPageTables {
        const page_table_allocation = try page_allocator.allocate(page_allocator.context, allocated_size, lib.arch.valid_page_sizes[0], .{});

        const page_tables = CPUPageTables{
            .pml4_table = page_table_allocation.address,
            .pdp_table = page_table_allocation.address.offset(0x1000),
            .pd_table = page_table_allocation.address.offset(0x2000),
            .p_table = page_table_allocation.address.offset(0x3000),
        };

        page_tables.pml4_table.toIdentityMappedVirtualAddress().access(*volatile PML4Table)[pml4_index] = PML4TE{
            .present = true,
            .read_write = true,
            .address = packAddress(PML4TE, page_tables.pdp_table.value()),
        };

        page_tables.pdp_table.toIdentityMappedVirtualAddress().access(*volatile PDPTable)[pdp_index] = PDPTE{
            .present = true,
            .read_write = true,
            .address = packAddress(PDPTE, page_tables.pd_table.value()),
        };

        page_tables.pd_table.toIdentityMappedVirtualAddress().access(*volatile PDTable)[pd_index] = PDTE{
            .present = true,
            .read_write = true,
            .address = packAddress(PDTE, page_tables.p_table.value()),
        };

        const p_table = page_tables.p_table.toIdentityMappedVirtualAddress().access(*volatile PTable);
        p_table[0x200 - 4] = .{
            .present = true,
            .read_write = true,
            .address = packAddress(PTE, page_tables.pml4_table.value()),
        };
        p_table[0x200 - 3] = .{
            .present = true,
            .read_write = true,
            .address = packAddress(PTE, page_tables.pdp_table.value()),
        };
        p_table[0x200 - 2] = .{
            .present = true,
            .read_write = true,
            .address = packAddress(PTE, page_tables.pd_table.value()),
        };
        p_table[0x200 - 1] = .{
            .present = true,
            .read_write = true,
            .address = packAddress(PTE, page_tables.p_table.value()),
        };

        return page_tables;
    }

    pub const MapError = error{
        lower_limit_exceeded,
        upper_limit_exceeded,
    };

    pub fn map(cpu_page_tables: CPUPageTables, asked_physical_address: PhysicalAddress, asked_virtual_address: VirtualAddress, size: u64, general_flags: Mapping.Flags) CPUPageTables.MapError!void {
        if (asked_virtual_address.value() < base) return CPUPageTables.MapError.lower_limit_exceeded;
        if (asked_virtual_address.offset(size).value() > top) return CPUPageTables.MapError.upper_limit_exceeded;

        const flags = general_flags.toArchitectureSpecific();
        const indices = computeIndices(asked_virtual_address.value());
        const index = indices[indices.len - 1];
        const iteration_count = @intCast(u32, size >> lib.arch.page_shifter(lib.arch.valid_page_sizes[0]));
        const p_table = cpu_page_tables.p_table.toIdentityMappedVirtualAddress().access(*volatile PTable);
        const p_table_slice = p_table[index .. index + iteration_count];

        var physical_address = asked_physical_address.value();

        for (p_table_slice) |*pte| {
            pte.* = @bitCast(PTE, getPageEntry(PTE, physical_address, flags));
            physical_address += 0x1000;
        }
    }
};

pub const Specific = extern struct {
    cr3: cr3 align(8),

    pub fn new(page_allocator: PageAllocator) !Specific {
        const pml4_physical_memory = try page_allocator.allocatePageTable(.PML4);
        // Already zeroed
        return .{
            .cr3 = cr3.fromAddress(pml4_physical_memory.address),
        };
    }

    pub fn fromPageTables(cpu_page_tables: CPUPageTables) Specific {
        return .{
            .cr3 = cr3.fromAddress(cpu_page_tables.pml4_table),
        };
    }

    pub noinline fn map(specific: Specific, asked_physical_address: PhysicalAddress, asked_virtual_address: VirtualAddress, size: u64, general_flags: Mapping.Flags, page_allocator: PageAllocator) !void {
        const flags = general_flags.toArchitectureSpecific();
        const top_virtual_address = asked_virtual_address.offset(size);

        inline for (reverse_valid_page_sizes, 0..) |reverse_page_size, reverse_page_index| {
            if (size >= reverse_page_size) {
                const is_smallest_page_size = reverse_page_index == reverse_valid_page_sizes.len - 1;

                if (is_smallest_page_size) {
                    var virtual_address = asked_virtual_address.value();
                    var physical_address = asked_physical_address.value();

                    while (virtual_address < top_virtual_address.value()) : ({
                        physical_address += reverse_page_size;
                        virtual_address += reverse_page_size;
                    }) {
                        try specific.map4KPage(physical_address, virtual_address, flags, page_allocator);
                    }

                    return;
                } else {
                    const aligned_page_address = alignForwardGeneric(u64, asked_virtual_address.value(), reverse_page_size);
                    const prologue_misalignment = aligned_page_address - asked_virtual_address.value();
                    const aligned_size_left = size - prologue_misalignment;

                    if (aligned_size_left >= reverse_page_size) {
                        if (prologue_misalignment != 0) {
                            try specific.map(asked_physical_address, asked_virtual_address, prologue_misalignment, general_flags, page_allocator);
                        }

                        const virtual_address = VirtualAddress.new(aligned_page_address);
                        const physical_address = asked_physical_address.offset(prologue_misalignment);
                        const this_page_top_physical_address = PhysicalAddress.new(alignBackwardGeneric(u64, physical_address.offset(aligned_size_left).value(), reverse_page_size));
                        const this_page_top_virtual_address = VirtualAddress.new(alignBackwardGeneric(u64, virtual_address.offset(aligned_size_left).value(), reverse_page_size));
                        const this_huge_page_size = this_page_top_virtual_address.value() - virtual_address.value();
                        try specific.mapGeneric(physical_address, virtual_address, this_huge_page_size, reverse_page_size, flags, page_allocator);

                        const epilogue_misalignment = top_virtual_address.value() - this_page_top_virtual_address.value();

                        if (epilogue_misalignment != 0) {
                            const epilogue_physical_address = this_page_top_physical_address;
                            const epilogue_virtual_address = this_page_top_virtual_address;

                            try specific.map(epilogue_physical_address, epilogue_virtual_address, epilogue_misalignment, general_flags, page_allocator);
                        }

                        return;
                    }
                }
            }
        }

        return MapError.no_region_found;
    }

    fn mapGeneric(specific: Specific, asked_physical_address: PhysicalAddress, asked_virtual_address: VirtualAddress, size: u64, comptime asked_page_size: comptime_int, flags: MemoryFlags, page_allocator: PageAllocator) !void {
        if (!isAlignedGeneric(u64, asked_physical_address.value(), asked_page_size)) {
            //log.debug("PA: {}. Page size: 0x{x}", .{ asked_physical_address, asked_page_size });
            @panic("Misaligned physical address in mapGeneric");
        }
        if (!isAlignedGeneric(u64, asked_virtual_address.value(), asked_page_size)) {
            @panic("Misaligned virtual address in mapGeneric");
        }
        if (!isAlignedGeneric(u64, size, asked_page_size)) {
            //log.debug("Asked size: 0x{x}. Asked page size: 0x{x}", .{ size, asked_page_size });
            @panic("Misaligned size in mapGeneric");
        }

        var virtual_address = asked_virtual_address.value();
        var physical_address = asked_physical_address.value();
        const top_virtual_address = asked_virtual_address.offset(size).value();

        // TODO: batch better
        switch (asked_page_size) {
            // 1 GB
            lib.arch.valid_page_sizes[0] * page_table_entry_count * page_table_entry_count => {
                while (virtual_address < top_virtual_address) : ({
                    physical_address += asked_page_size;
                    virtual_address += asked_page_size;
                }) {
                    try specific.map1GBPage(physical_address, virtual_address, flags, page_allocator);
                }
            },
            // 2 MB
            lib.arch.valid_page_sizes[0] * page_table_entry_count => {
                while (virtual_address < top_virtual_address) : ({
                    physical_address += asked_page_size;
                    virtual_address += asked_page_size;
                }) {
                    try specific.map2MBPage(physical_address, virtual_address, flags, page_allocator);
                }
            },
            // Smallest: 4 KB
            lib.arch.valid_page_sizes[0] => {
                while (virtual_address < top_virtual_address) : ({
                    physical_address += asked_page_size;
                    virtual_address += asked_page_size;
                }) {
                    try specific.map4KPage(physical_address, virtual_address, flags, page_allocator);
                }
            },
            else => @compileError("Invalid reverse valid page size"),
        }
    }

    fn map1GBPage(specific: Specific, physical_address: u64, virtual_address: u64, flags: MemoryFlags, page_allocator: PageAllocator) !void {
        const indices = computeIndices(virtual_address);

        const pml4_table = getPML4Table(specific.cr3) catch @panic("1G PML4"); //privileged.panic("[1G] PML4 access failed when mapping 0x{x} -> 0x{x}", .{ virtual_address, physical_address });
        const pdp_table = getPDPTable(pml4_table, indices, flags, page_allocator) catch @panic("1G PDP"); //privileged.panic("[1G] PDP table access failed when mapping 0x{x} -> 0x{x}", .{ virtual_address, physical_address });

        try mapPageTable1GB(pdp_table, indices, physical_address, flags);

        // const translated_physical_address = translateAddress(virtual_address_space, VirtualAddress.new(virtual_address)) catch |err| {
        //     log.err("Error when mapping 1GB page (0x{x} -> 0x{x}): {}", .{ virtual_address, physical_address, err });
        //     return MapError.validation_failed;
        // };
        //
        // if (physical_address != translated_physical_address.value()) {
        //     log.err("Given: 0x{x}. Have: 0x{x}", .{ physical_address, translated_physical_address.value() });
        //     return MapError.validation_failed;
        // }
    }

    fn map2MBPage(specific: Specific, physical_address: u64, virtual_address: u64, flags: MemoryFlags, page_allocator: PageAllocator) !void {
        const indices = computeIndices(virtual_address);

        const pml4_table = getPML4Table(specific.cr3) catch @panic("2M pml4"); //privileged.panic("[2M] PML4 access failed when mapping 0x{x} -> 0x{x}", .{ virtual_address, physical_address });
        const pdp_table = getPDPTable(pml4_table, indices, flags, page_allocator) catch @panic("2M pdp"); //catch privileged.panic("[2M] PDP table access failed when mapping 0x{x} -> 0x{x}", .{ virtual_address, physical_address });
        const pd_table = getPDTable(pdp_table, indices, flags, page_allocator) catch @panic("2m pd"); //catch privileged.panic("[2M] PD table access failed when mapping 0x{x} -> 0x{x}", .{ virtual_address, physical_address });

        mapPageTable2MB(pd_table, indices, physical_address, flags) catch |err| {
            log.err("Virtual address: 0x{x}. Physical address: 0x{x}", .{ virtual_address, physical_address });
            return err;
        };

        // const translated_physical_address = translateAddress(virtual_address_space, VirtualAddress.new(virtual_address)) catch |err| {
        //     log.err("Error when mapping 2MB page (0x{x} -> 0x{x}): {}", .{ virtual_address, physical_address, err });
        //     return MapError.validation_failed;
        // };
        //
        // if (physical_address != translated_physical_address.value()) {
        //     log.err("Given: 0x{x}. Have: 0x{x}", .{ physical_address, translated_physical_address.value() });
        //     return MapError.validation_failed;
        // }
    }

    fn map4KPage(specific: Specific, physical_address: u64, virtual_address: u64, flags: MemoryFlags, page_allocator: PageAllocator) !void {
        const indices = computeIndices(virtual_address);

        const pml4_table = try getPML4Table(specific.cr3);
        // for (pml4_table) |pml4e| {
        //     log.debug("PML4 table: 0x{x}", .{@bitCast(u64, pml4e)});
        // }
        const pdp_table = try getPDPTable(pml4_table, indices, flags, page_allocator);
        const pd_table = try getPDTable(pdp_table, indices, flags, page_allocator);
        const p_table = try getPTable(pd_table, indices, flags, page_allocator);
        try mapPageTable4KB(p_table, indices, physical_address, flags);
    }

    pub inline fn switchTo(specific: *Specific, execution_mode: lib.TraditionalExecutionMode) void {
        const mask = ~@as(u64, 1 << 12);
        const masked_cr3 = (@bitCast(u64, specific.cr3) & mask);
        const privileged_or = (@as(u64, @enumToInt(execution_mode)) << 12);
        const new_cr3 = @bitCast(cr3, masked_cr3 | privileged_or);
        specific.cr3 = new_cr3;
    }

    pub inline fn copyHigherHalfCommon(cpu_specific: Specific, pml4_physical_address: PhysicalAddress) void {
        const cpu_side_pml4_table = pml4_physical_address.toHigherHalfVirtualAddress().access(*PML4Table);
        const privileged_cpu_pml4_table = try getPML4Table(cpu_specific.cr3);
        for (cpu_side_pml4_table[0x100..], privileged_cpu_pml4_table[0x100..]) |*pml4_entry, cpu_pml4_entry| {
            pml4_entry.* = cpu_pml4_entry;
        }
    }

    pub fn copyHigherHalfPrivileged(cpu_specific: Specific, pml4_physical_address: PhysicalAddress) void {
        cpu_specific.copyHigherHalfCommon(pml4_physical_address);
    }

    pub fn copyHigherHalfUser(cpu_specific: Specific, pml4_physical_address: PhysicalAddress, page_allocator: *PageAllocator) !void {
        cpu_specific.copyHigherHalfCommon(pml4_physical_address);

        const pml4_table = pml4_physical_address.toHigherHalfVirtualAddress().access(*PML4Table);
        const pml4_entry = pml4_table[0x1ff];
        const pml4_entry_address = PhysicalAddress.new(unpackAddress(pml4_entry));
        const pdp_table = pml4_entry_address.toHigherHalfVirtualAddress().access(*PDPTable);
        const new_pdp_table_allocation = try page_allocator.allocate(0x1000, 0x1000);
        const new_pdp_table = new_pdp_table_allocation.toHigherHalfVirtualAddress().access(PDPTE);
        lib.copy(PDPTE, new_pdp_table, pdp_table);
        new_pdp_table[0x1fd] = @bitCast(PDPTE, @as(u64, 0));
    }

    pub fn translateAddress(specific: Specific, virtual_address: VirtualAddress) !PhysicalAddress {
        const indices = computeIndices(virtual_address.value());

        const pml4_table = try getPML4Table(specific.cr3);
        const pml4_entry = pml4_table[indices[@enumToInt(Level.PML4)]];
        if (!pml4_entry.present) {
            return TranslateError.pml4_entry_not_present;
        }

        if (pml4_entry.execute_disable) {
            @panic("PML4");
        }

        const pml4_entry_address = PhysicalAddress.new(unpackAddress(pml4_entry));
        if (pml4_entry_address.value() == 0) {
            return TranslateError.pml4_entry_address_null;
        }

        const pdp_table = try getPDPTable(pml4_table, indices, undefined, null);
        const pdp_entry = &pdp_table[indices[@enumToInt(Level.PDP)]];
        if (!pdp_entry.present) {
            return TranslateError.pdp_entry_not_present;
        }
        if (pdp_entry.execute_disable) {
            @panic("PDP");
        }

        if (pdp_entry.page_size) {
            const pdp_entry_1gb = @bitCast(PDPTE_1GB, pdp_entry.*);
            const entry_address_value = unpackAddress(pdp_entry_1gb);
            const physical_address = PhysicalAddress.new(entry_address_value);
            if (lib.isAlignedGeneric(u64, virtual_address.value(), lib.gb)) {
                return physical_address;
            } else {
                @panic("unaligned 1gb");
            }
        }

        const pdp_entry_address = PhysicalAddress.new(unpackAddress(pdp_entry.*));
        if (pdp_entry_address.value() == 0) {
            return TranslateError.pdp_entry_address_null;
        }

        const pd_table = try accessPageTable(pdp_entry_address, *volatile PDTable);
        const pd_entry = pd_table[indices[@enumToInt(Level.PD)]];
        if (!pd_entry.present) {
            return TranslateError.pd_entry_not_present;
        }
        if (pd_entry.execute_disable) {
            @panic("PD");
        }

        if (pd_entry.page_size) {
            const pd_entry_2mb = @bitCast(PDTE_2MB, pd_entry);
            const entry_address_value = unpackAddress(pd_entry_2mb);
            const physical_address = PhysicalAddress.new(entry_address_value);
            if (lib.isAlignedGeneric(u64, virtual_address.value(), 2 * lib.mb)) {
                return physical_address;
            } else {
                @panic("unaligned 2mb");
            }
        }

        const pd_entry_address = PhysicalAddress.new(unpackAddress(pd_entry));
        if (pd_entry_address.value() == 0) {
            return TranslateError.pd_entry_address_null;
        }

        const p_table = try accessPageTable(pd_entry_address, *volatile PTable);
        const pt_entry = &p_table[indices[@enumToInt(Level.PT)]];
        if (!pt_entry.present) {
            return TranslateError.pt_entry_not_present;
        }

        if (pt_entry.execute_disable) {
            log.debug("PTR: 0x{x}", .{@ptrToInt(pt_entry)});
            // @panic("PT");
        }

        const pt_entry_address = PhysicalAddress.new(unpackAddress(pt_entry.*));
        if (pt_entry_address.value() == 0) {
            return TranslateError.pt_entry_address_null;
        }

        return pt_entry_address;
    }
};

const Indices = [enumCount(Level)]u16;

const MapError = error{
    already_present_4kb,
    already_present_2mb,
    already_present_1gb,
    validation_failed,
    no_region_found,
};

pub const Error = error{
    invalid_physical,
    invalid_virtual,
    invalid_size,
    unaligned_physical,
    unaligned_virtual,
    unaligned_size,
};

pub const TranslateError = error{
    pml4_entry_not_present,
    pml4_entry_address_null,
    pdp_entry_not_present,
    pdp_entry_address_null,
    pd_entry_not_present,
    pd_entry_address_null,
    pt_entry_not_present,
    pt_entry_address_null,
};

pub fn accessPageTable(physical_address: PhysicalAddress, comptime Pointer: type) !Pointer {
    const virtual_address = switch (lib.cpu.arch) {
        .x86 => physical_address.toIdentityMappedVirtualAddress(),
        .x86_64 => switch (lib.os) {
            .freestanding => physical_address.toHigherHalfVirtualAddress(),
            .uefi => physical_address.toIdentityMappedVirtualAddress(),
            else => @compileError("OS not supported"),
        },
        else => @compileError("Architecture not supported"),
    };

    return switch (lib.cpu.arch) {
        .x86 => @intToPtr(Pointer, try lib.tryDereferenceAddress(virtual_address.value())),
        else => virtual_address.access(Pointer),
    };
}

fn getPML4Table(cr3r: cr3) !*volatile PML4Table {
    const pml4_table = try accessPageTable(cr3r.getAddress(), *volatile PML4Table);
    return pml4_table;
}

fn getPDPTable(pml4_table: *volatile PML4Table, indices: Indices, flags: MemoryFlags, maybe_page_allocator: ?PageAllocator) !*volatile PDPTable {
    const index = indices[@enumToInt(Level.PML4)];
    const entry_pointer = &pml4_table[index];

    const table_physical_address = physical_address_blk: {
        const entry_value = entry_pointer.*;
        if (entry_value.present) {
            const entry_address = unpackAddress(entry_value);
            break :physical_address_blk PhysicalAddress.new(entry_address);
        } else {
            if (maybe_page_allocator) |page_allocator| {
                // TODO: track this physical allocation in order to map it later in the kernel address space
                const entry_allocation = try page_allocator.allocate(page_allocator.context, @sizeOf(PDPTable), 0x1000, .{});

                entry_pointer.* = PML4TE{
                    .present = true,
                    .read_write = true,
                    .user = flags.user,
                    .address = packAddress(PML4TE, entry_allocation.address.value()),
                };

                break :physical_address_blk entry_allocation.address;
            } else {
                return Allocator.Allocate.Error.OutOfMemory;
            }
        }
    };

    return try accessPageTable(table_physical_address, *volatile PDPTable);
}

inline fn getPageEntry(comptime Entry: type, physical_address: u64, flags: MemoryFlags) Entry {
    return Entry{
        .present = true,
        .read_write = flags.read_write,
        .user = flags.user,
        .page_level_cache_disable = flags.cache_disable,
        .global = flags.global,
        .pat = flags.pat,
        .address = packAddress(Entry, physical_address),
        .execute_disable = flags.execute_disable,
    };
}

fn mapPageTable1GB(pdp_table: *volatile PDPTable, indices: Indices, physical_address: u64, flags: MemoryFlags) MapError!void {
    const entry_index = indices[@enumToInt(Level.PDP)];
    const entry_pointer = &pdp_table[entry_index];

    if (entry_pointer.present) return MapError.already_present_1gb;

    assert(isAlignedGeneric(u64, physical_address, valid_page_sizes[2]));

    entry_pointer.* = @bitCast(PDPTE, getPageEntry(PDPTE_1GB, physical_address, flags));
}

fn mapPageTable2MB(pd_table: *volatile PDTable, indices: Indices, physical_address: u64, flags: MemoryFlags) !void {
    const entry_index = indices[@enumToInt(Level.PD)];
    const entry_pointer = &pd_table[entry_index];
    const entry_value = entry_pointer.*;

    if (entry_value.present) {
        log.err("Already mapped to: 0x{x}", .{unpackAddress(entry_value)});
        return MapError.already_present_2mb;
    }

    assert(isAlignedGeneric(u64, physical_address, valid_page_sizes[1]));

    entry_pointer.* = @bitCast(PDTE, getPageEntry(PDTE_2MB, physical_address, flags));
}

fn mapPageTable4KB(p_table: *volatile PTable, indices: Indices, physical_address: u64, flags: MemoryFlags) !void {
    const entry_index = indices[@enumToInt(Level.PT)];
    const entry_pointer = &p_table[entry_index];

    if (entry_pointer.present) {
        log.err("PTable address: 0x{x}, entry_index: {}, entry_pointer: 0x{x}", .{ @ptrToInt(p_table), entry_index, @ptrToInt(entry_pointer) });
        return MapError.already_present_4kb;
    }

    assert(isAlignedGeneric(u64, physical_address, valid_page_sizes[0]));

    entry_pointer.* = @bitCast(PTE, getPageEntry(PTE, physical_address, flags));
}

fn getPDTable(pdp_table: *volatile PDPTable, indices: Indices, flags: MemoryFlags, page_allocator: PageAllocator) !*volatile PDTable {
    const entry_index = indices[@enumToInt(Level.PDP)];
    const entry_pointer = &pdp_table[entry_index];

    const table_physical_address = physical_address_blk: {
        const entry_value = entry_pointer.*;
        if (entry_value.present) {
            // The address is mapped with a 1GB page
            if (entry_value.page_size) {
                @panic("todo pd table page size");
            }
            break :physical_address_blk PhysicalAddress.new(unpackAddress(entry_value));
        } else {
            // TODO: track this physical allocation in order to map it later in the kernel address space
            const entry_allocation = try page_allocator.allocate(page_allocator.context, @sizeOf(PDTable), 0x1000, .{});

            entry_pointer.* = PDPTE{
                .present = true,
                .read_write = true,
                .user = flags.user,
                .address = packAddress(PDPTE, entry_allocation.address.value()),
            };

            break :physical_address_blk entry_allocation.address;
        }
    };

    return try accessPageTable(table_physical_address, *volatile PDTable);
}

fn getPTable(pd_table: *volatile PDTable, indices: Indices, flags: MemoryFlags, page_allocator: PageAllocator) !*volatile PTable {
    const entry_pointer = &pd_table[indices[@enumToInt(Level.PD)]];
    const table_physical_address = physical_address_blk: {
        const entry_value = entry_pointer.*;
        if (entry_value.present) {
            // The address is mapped with a 2MB page
            if (entry_value.page_size) {
                @panic("todo ptable page size");
            }
            break :physical_address_blk PhysicalAddress.new(unpackAddress(entry_value));
        } else {
            const entry_allocation = try page_allocator.allocate(page_allocator.context, @sizeOf(PTable), 0x1000, .{});

            entry_pointer.* = PDTE{
                .present = true,
                .read_write = true,
                .user = flags.user,
                .address = packAddress(PDTE, entry_allocation.address.value()),
            };

            break :physical_address_blk entry_allocation.address;
        }
    };

    return try accessPageTable(table_physical_address, *volatile PTable);
}

const half_entry_count = (@sizeOf(PML4Table) / @sizeOf(PML4TE)) / 2;

const needed_physical_memory_for_bootstrapping_cpu_driver_address_space = @sizeOf(PML4Table) + @sizeOf(PDPTable) * 256;

fn computeIndices(virtual_address: u64) Indices {
    var indices: Indices = undefined;
    var va = virtual_address;
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

pub inline fn newFlags(general_flags: Mapping.Flags) MemoryFlags {
    return MemoryFlags{
        .read_write = general_flags.write,
        .user = general_flags.user,
        .cache_disable = general_flags.cache_disable,
        .global = general_flags.global,
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

pub const Level = enum(u2) {
    PML4 = 0,
    PDP = 1,
    PD = 2,
    PT = 3,
};

inline fn unpackAddress(entry: anytype) u64 {
    const T = @TypeOf(entry);
    const address_offset = @bitOffsetOf(T, "address");
    return @as(u64, entry.address) << address_offset;
}

fn AddressType(comptime T: type) type {
    var a: T = undefined;
    return @TypeOf(@field(a, "address"));
}

fn packAddress(comptime T: type, physical_address: u64) AddressType(T) {
    assert(physical_address < lib.config.cpu_driver_higher_half_address);
    const address_offset = @bitOffsetOf(T, "address");
    return @intCast(AddressType(T), physical_address >> address_offset);
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
    reserved2: u19 = 0,
    protection_key: u4 = 0,
    execute_disable: bool = false,

    comptime {
        assert(@sizeOf(@This()) == @sizeOf(u64));
        assert(@bitSizeOf(@This()) == @bitSizeOf(u64));
    }
};

pub const PML4Table = [page_table_entry_count]PML4TE;
pub const PDPTable = [page_table_entry_count]PDPTE;
pub const PDTable = [page_table_entry_count]PDTE;
pub const PTable = [page_table_entry_count]PTE;
pub const page_table_entry_size = @sizeOf(u64);
pub const page_table_size = lib.arch.valid_page_sizes[0];
pub const page_table_entry_count = @divExact(page_table_size, page_table_entry_size);
pub const page_table_alignment = page_table_size;

comptime {
    assert(page_table_alignment == page_table_size);
    assert(page_table_size == lib.arch.valid_page_sizes[0]);
}

pub fn setMappingFlags(specific: Specific, virtual_address: u64, flags: Mapping.Flags) !void {
    const indices = computeIndices(virtual_address);

    const vas_cr3 = specific.cr3;

    const pml4_physical_address = vas_cr3.getAddress();

    const pml4_table = try accessPageTable(pml4_physical_address, *volatile PML4Table);
    const pml4_entry = pml4_table[indices[@enumToInt(Level.PML4)]];
    if (!pml4_entry.present) {
        return TranslateError.pml4_entry_not_present;
    }

    const pml4_entry_address = PhysicalAddress.new(unpackAddress(pml4_entry));
    if (pml4_entry_address.value() == 0) {
        return TranslateError.pml4_entry_address_null;
    }

    const pdp_table = try accessPageTable(pml4_entry_address, *volatile PDPTable);
    const pdp_entry = pdp_table[indices[@enumToInt(Level.PDP)]];
    if (!pdp_entry.present) {
        return TranslateError.pdp_entry_not_present;
    }

    const pdp_entry_address = PhysicalAddress.new(unpackAddress(pdp_entry));
    if (pdp_entry_address.value() == 0) {
        return TranslateError.pdp_entry_address_null;
    }

    const pd_table = try accessPageTable(pdp_entry_address, *volatile PDTable);
    const pd_entry = pd_table[indices[@enumToInt(Level.PD)]];
    if (!pd_entry.present) {
        return TranslateError.pd_entry_not_present;
    }

    const pd_entry_address = PhysicalAddress.new(unpackAddress(pd_entry));
    if (pd_entry_address.value() == 0) {
        return TranslateError.pd_entry_address_null;
    }

    const pt_table = try accessPageTable(pd_entry_address, *volatile PTable);
    const pt_entry = &pt_table[indices[@enumToInt(Level.PT)]];
    if (!pt_entry.present) {
        return TranslateError.pd_entry_not_present;
    }

    pt_entry.read_write = flags.write;
    pt_entry.user = flags.user;
    pt_entry.page_level_cache_disable = flags.cache_disable;
    pt_entry.global = flags.global;
    pt_entry.execute_disable = !flags.execute;
}

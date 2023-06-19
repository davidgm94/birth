const lib = @import("lib");
const alignForward = lib.alignForward;
const alignBackward = lib.alignBackward;
const isAligned = lib.isAligned;
const isAlignedGeneric = lib.isAlignedGeneric;
const assert = lib.assert;
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
const PhysicalAddress = lib.PhysicalAddress;
const VirtualAddress = lib.VirtualAddress;
const PhysicalMemoryRegion = lib.PhysicalMemoryRegion;
const PhysicalAddressSpace = lib.PhysicalAddressSpace;
const Mapping = privileged.Mapping;

const bootloader = @import("bootloader");

const page_table_level_count = 4;
pub const page_table_mask = page_table_entry_count - 1;

pub fn entryCount(comptime level: Level, limit: u64) u10 {
    const index = baseFromVirtualAddress(level, limit - 1);
    const result = @as(u10, index) + 1;
    // @compileLog(limit, index, result);
    return result;
}

// Comptime test
comptime {
    const va = 134217728;
    const indices = computeIndices(va);
    const pml4_index = baseFromVirtualAddress(.PML4, va);
    const pdp_index = baseFromVirtualAddress(.PDP, va);
    const pd_index = baseFromVirtualAddress(.PD, va);
    const pt_index = baseFromVirtualAddress(.PT, va);
    assert(pml4_index == indices[@intFromEnum(Level.PML4)]);
    assert(pdp_index == indices[@intFromEnum(Level.PDP)]);
    assert(pd_index == indices[@intFromEnum(Level.PD)]);
    assert(pt_index == indices[@intFromEnum(Level.PT)]);
}

const max_level_possible = 5;
pub const IndexedVirtualAddress = packed struct(u64) {
    page_offset: u12 = 0,
    PT: u9 = 0,
    PD: u9 = 0,
    PDP: u9 = 0,
    PML4: u9 = 0,
    _: u16 = 0,

    pub fn toVirtualAddress(indexed_virtual_address: IndexedVirtualAddress) VirtualAddress {
        const raw = @as(u64, @bitCast(indexed_virtual_address));
        if (indexed_virtual_address.PML4 & 0x100 != 0) {
            return VirtualAddress.new(raw | 0xffff_0000_0000_0000);
        } else {
            return VirtualAddress.new(raw);
        }
    }
};

pub fn baseFromVirtualAddress(comptime level: Level, virtual_address: u64) u9 {
    const indexed = @as(IndexedVirtualAddress, @bitCast(virtual_address));
    return @field(indexed, @tagName(level));
}

pub const CPUPageTables = extern struct {
    pml4_table: PhysicalAddress,
    pdp_table: PhysicalAddress,
    pd_table: PhysicalAddress,
    p_table: PhysicalAddress,

    const base = 0xffff_ffff_8000_0000;
    const top = base + pte_count * lib.arch.valid_page_sizes[0];
    const pte_count = page_table_entry_count - left_ptables;
    pub const left_ptables = 4;
    pub const pml4_index = 0x1ff;
    pub const pdp_index = 0x1fe;
    pub const pd_index = 0;
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

        page_tables.pml4_table.toIdentityMappedVirtualAddress().access(*PML4Table)[pml4_index] = PML4TE{
            .present = true,
            .write = true,
            .address = packAddress(PML4TE, page_tables.pdp_table.value()),
        };

        page_tables.pdp_table.toIdentityMappedVirtualAddress().access(*PDPTable)[pdp_index] = PDPTE{
            .present = true,
            .write = true,
            .address = packAddress(PDPTE, page_tables.pd_table.value()),
        };

        page_tables.pd_table.toIdentityMappedVirtualAddress().access(*PDTable)[pd_index] = PDTE{
            .present = true,
            .write = true,
            .address = packAddress(PDTE, page_tables.p_table.value()),
        };

        const p_table = page_tables.p_table.toIdentityMappedVirtualAddress().access(*PTable);
        p_table[0x200 - 4] = .{
            .present = true,
            .write = true,
            .address = packAddress(PTE, page_tables.pml4_table.value()),
        };
        p_table[0x200 - 3] = .{
            .present = true,
            .write = true,
            .address = packAddress(PTE, page_tables.pdp_table.value()),
        };
        p_table[0x200 - 2] = .{
            .present = true,
            .write = true,
            .address = packAddress(PTE, page_tables.pd_table.value()),
        };
        p_table[0x200 - 1] = .{
            .present = true,
            .write = true,
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
        const iteration_count = @as(u32, @intCast(size >> lib.arch.page_shifter(lib.arch.valid_page_sizes[0])));
        const p_table = cpu_page_tables.p_table.toIdentityMappedVirtualAddress().access(*PTable);
        const p_table_slice = p_table[index .. index + iteration_count];

        var physical_address = asked_physical_address.value();

        for (p_table_slice) |*pte| {
            pte.* = @as(PTE, @bitCast(getPageEntry(PTE, physical_address, flags)));
            physical_address += 0x1000;
        }
    }
};

pub const Specific = extern struct {
    cr3: cr3 align(8),

    pub inline fn makeCurrent(specific: Specific) void {
        specific.getUserCr3().write();
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
                    const aligned_page_address = alignForward(u64, asked_virtual_address.value(), reverse_page_size);
                    const prologue_misalignment = aligned_page_address - asked_virtual_address.value();
                    const aligned_size_left = size - prologue_misalignment;

                    if (aligned_size_left >= reverse_page_size) {
                        if (prologue_misalignment != 0) {
                            try specific.map(asked_physical_address, asked_virtual_address, prologue_misalignment, general_flags, page_allocator);
                        }

                        const virtual_address = VirtualAddress.new(aligned_page_address);
                        const physical_address = asked_physical_address.offset(prologue_misalignment);
                        const this_page_top_physical_address = PhysicalAddress.new(alignBackward(u64, physical_address.offset(aligned_size_left).value(), reverse_page_size));
                        const this_page_top_virtual_address = VirtualAddress.new(alignBackward(u64, virtual_address.offset(aligned_size_left).value(), reverse_page_size));
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

        const pml4_table = try getPML4Table(specific.cr3);
        const pdp_table = try getPDPTable(pml4_table, indices, flags, page_allocator);
        try mapPageTable1GB(pdp_table, indices, physical_address, flags);
    }

    fn map2MBPage(specific: Specific, physical_address: u64, virtual_address: u64, flags: MemoryFlags, page_allocator: PageAllocator) !void {
        const indices = computeIndices(virtual_address);

        const pml4_table = try getPML4Table(specific.cr3);
        const pdp_table = try getPDPTable(pml4_table, indices, flags, page_allocator);
        const pd_table = try getPDTable(pdp_table, indices, flags, page_allocator);

        mapPageTable2MB(pd_table, indices, physical_address, flags) catch |err| {
            log.err("Virtual address: 0x{x}. Physical address: 0x{x}", .{ virtual_address, physical_address });
            return err;
        };
    }

    fn map4KPage(specific: Specific, physical_address: u64, virtual_address: u64, flags: MemoryFlags, page_allocator: PageAllocator) !void {
        const indices = computeIndices(virtual_address);

        const pml4_table = try getPML4Table(specific.cr3);
        const pdp_table = try getPDPTable(pml4_table, indices, flags, page_allocator);
        const pd_table = try getPDTable(pdp_table, indices, flags, page_allocator);
        const p_table = try getPTable(pd_table, indices, flags, page_allocator);
        try mapPageTable4KB(p_table, indices, physical_address, flags);
    }

    pub inline fn switchTo(specific: *Specific, execution_mode: lib.TraditionalExecutionMode) void {
        const mask = ~@as(u64, 1 << 12);
        const masked_cr3 = (@as(u64, @bitCast(specific.cr3)) & mask);
        const privileged_or = (@as(u64, @intFromEnum(execution_mode)) << 12);
        const new_cr3 = @as(cr3, @bitCast(masked_cr3 | privileged_or));
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
        @memcpy(new_pdp_table, pdp_table);
        new_pdp_table[0x1fd] = @as(PDPTE, @bitCast(@as(u64, 0)));
    }

    pub const TranslateError = error{
        pml4_entry_not_present,
        pml4_entry_address_null,
        pdp_entry_not_present,
        pdp_entry_address_null,
        pd_entry_not_present,
        pd_entry_address_null,
        pt_entry_not_present,
        pt_entry_address_null,
        flags_not_respected,
    };

    pub fn translateAddress(specific: Specific, virtual_address: VirtualAddress, flags: MemoryFlags) !PhysicalAddress {
        const indices = computeIndices(virtual_address.value());
        const is_desired = virtual_address.value() == 0xffff_ffff_8001_f000;

        const pml4_table = try getPML4Table(specific.cr3);
        // if (is_desired) {
        //     _ = try specific.translateAddress(VirtualAddress.new(@ptrToInt(pml4_table)), .{});
        // }

        //log.debug("pml4 table: 0x{x}", .{@ptrToInt(pml4_table)});
        const pml4_index = indices[@intFromEnum(Level.PML4)];
        const pml4_entry = pml4_table[pml4_index];
        if (!pml4_entry.present) {
            log.err("Virtual address: 0x{x}.\nPML4 index: {}.\nValue: {}\n", .{ virtual_address.value(), pml4_index, pml4_entry });
            return TranslateError.pml4_entry_not_present;
        }

        if (pml4_entry.execute_disable and !flags.execute_disable) {
            return TranslateError.flags_not_respected;
        }

        const pml4_entry_address = PhysicalAddress.new(unpackAddress(pml4_entry));
        if (pml4_entry_address.value() == 0) {
            return TranslateError.pml4_entry_address_null;
        }

        const pdp_table = try getPDPTable(pml4_table, indices, undefined, null);
        if (is_desired) {
            _ = try specific.translateAddress(VirtualAddress.new(@intFromPtr(pdp_table)), .{});
        }
        //log.debug("pdp table: 0x{x}", .{@ptrToInt(pdp_table)});
        const pdp_index = indices[@intFromEnum(Level.PDP)];
        const pdp_entry = &pdp_table[pdp_index];
        if (!pdp_entry.present) {
            log.err("PDP index {} not present in PDP table 0x{x}", .{ pdp_index, @intFromPtr(pdp_table) });
            return TranslateError.pdp_entry_not_present;
        }

        if (pdp_entry.execute_disable and !flags.execute_disable) {
            return TranslateError.flags_not_respected;
        }

        if (pdp_entry.page_size) {
            const pdp_entry_1gb = @as(PDPTE_1GB, @bitCast(pdp_entry.*));
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

        const pd_table = try accessPageTable(pdp_entry_address, *PDTable);
        if (is_desired) {
            _ = try specific.translateAddress(VirtualAddress.new(@intFromPtr(pd_table)), .{});
        }
        //log.debug("pd table: 0x{x}", .{@ptrToInt(pd_table)});
        const pd_index = indices[@intFromEnum(Level.PD)];
        const pd_entry = &pd_table[pd_index];
        if (!pd_entry.present) {
            log.err("PD index: {}", .{pd_index});
            log.err("PD entry: 0x{x}", .{@intFromPtr(pd_entry)});
            return TranslateError.pd_entry_not_present;
        }

        if (pd_entry.execute_disable and !flags.execute_disable) {
            return TranslateError.flags_not_respected;
        }

        if (pd_entry.page_size) {
            const pd_entry_2mb = @as(PDTE_2MB, @bitCast(pd_entry.*));
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

        const p_table = try accessPageTable(pd_entry_address, *PTable);
        if (is_desired) {
            _ = try specific.translateAddress(VirtualAddress.new(@intFromPtr(p_table)), .{});
        }
        // log.debug("p table: 0x{x}", .{@ptrToInt(p_table)});
        const pt_index = indices[@intFromEnum(Level.PT)];
        const pt_entry = &p_table[pt_index];
        if (!pt_entry.present) {
            log.err("Virtual address 0x{x} not mapped", .{virtual_address.value()});
            log.err("Indices: {any}", .{indices});
            log.err("PTE: 0x{x}", .{@intFromPtr(pt_entry)});
            log.err("PDE: 0x{x}", .{@intFromPtr(pd_entry)});
            log.err("PDPE: 0x{x}", .{@intFromPtr(pdp_entry)});
            return TranslateError.pt_entry_not_present;
        }

        if (pt_entry.execute_disable and !flags.execute_disable) {
            return TranslateError.flags_not_respected;
        }

        const pt_entry_address = PhysicalAddress.new(unpackAddress(pt_entry.*));
        if (pt_entry_address.value() == 0) {
            return TranslateError.pt_entry_address_null;
        }

        return pt_entry_address;
    }

    pub fn setMappingFlags(specific: Specific, virtual_address: u64, flags: Mapping.Flags) !void {
        const indices = computeIndices(virtual_address);

        const vas_cr3 = specific.cr3;

        const pml4_physical_address = vas_cr3.getAddress();

        const pml4_table = try accessPageTable(pml4_physical_address, *PML4Table);
        const pml4_entry = pml4_table[indices[@intFromEnum(Level.PML4)]];
        if (!pml4_entry.present) {
            return TranslateError.pml4_entry_not_present;
        }

        const pml4_entry_address = PhysicalAddress.new(unpackAddress(pml4_entry));
        if (pml4_entry_address.value() == 0) {
            return TranslateError.pml4_entry_address_null;
        }

        const pdp_table = try accessPageTable(pml4_entry_address, *PDPTable);
        const pdp_entry = pdp_table[indices[@intFromEnum(Level.PDP)]];
        if (!pdp_entry.present) {
            return TranslateError.pdp_entry_not_present;
        }

        const pdp_entry_address = PhysicalAddress.new(unpackAddress(pdp_entry));
        if (pdp_entry_address.value() == 0) {
            return TranslateError.pdp_entry_address_null;
        }

        const pd_table = try accessPageTable(pdp_entry_address, *PDTable);
        const pd_entry = pd_table[indices[@intFromEnum(Level.PD)]];
        if (!pd_entry.present) {
            return TranslateError.pd_entry_not_present;
        }

        const pd_entry_address = PhysicalAddress.new(unpackAddress(pd_entry));
        if (pd_entry_address.value() == 0) {
            return TranslateError.pd_entry_address_null;
        }

        const pt_table = try accessPageTable(pd_entry_address, *PTable);
        const pt_entry = &pt_table[indices[@intFromEnum(Level.PT)]];
        if (!pt_entry.present) {
            return TranslateError.pd_entry_not_present;
        }

        pt_entry.write = flags.write;
        pt_entry.user = flags.user;
        pt_entry.page_level_cache_disable = flags.cache_disable;
        pt_entry.global = flags.global;
        pt_entry.execute_disable = !flags.execute;
    }

    pub fn debugMemoryMap(specific: Specific) !void {
        log.debug("[START] Memory map dump 0x{x}\n", .{specific.cr3.getAddress().value()});

        const pml4 = try specific.getCpuPML4Table();

        for (pml4, 0..) |*pml4te, pml4_index| {
            if (pml4te.present) {
                const pdp_table = try accessPageTable(PhysicalAddress.new(unpackAddress(pml4te.*)), *PDPTable);

                for (pdp_table, 0..) |*pdpte, pdp_index| {
                    if (pdpte.present) {
                        if (pdpte.page_size) {
                            continue;
                        }

                        const pd_table = try accessPageTable(PhysicalAddress.new(unpackAddress(pdpte.*)), *PDTable);

                        for (pd_table, 0..) |*pdte, pd_index| {
                            if (pdte.present) {
                                if (pdte.page_size) @panic("bbbb");

                                const p_table = try accessPageTable(PhysicalAddress.new(unpackAddress(pdte.*)), *PTable);

                                for (p_table, 0..) |*pte, pt_index| {
                                    if (pte.present) {
                                        const indexed_virtual_address = IndexedVirtualAddress{
                                            .PML4 = @as(u9, @intCast(pml4_index)),
                                            .PDP = @as(u9, @intCast(pdp_index)),
                                            .PD = @as(u9, @intCast(pd_index)),
                                            .PT = @as(u9, @intCast(pt_index)),
                                        };

                                        const virtual_address = indexed_virtual_address.toVirtualAddress();
                                        const physical_address = unpackAddress(pte.*);
                                        log.debug("0x{x} -> 0x{x}", .{ virtual_address.value(), physical_address });
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        log.debug("[END] Memory map dump", .{});
    }

    inline fn getUserCr3(specific: Specific) cr3 {
        assert(@as(u64, @bitCast(specific.cr3)) & page_table_size == 0);
        return @as(cr3, @bitCast(@as(u64, @bitCast(specific.cr3)) | page_table_size));
    }

    pub inline fn getCpuPML4Table(specific: Specific) !*PML4Table {
        assert(@as(u64, @bitCast(specific.cr3)) & page_table_size == 0);
        return try specific.getPML4TableUnchecked();
    }
    pub inline fn getUserPML4Table(specific: Specific) !*PML4Table {
        return try getPML4Table(specific.getUserCr3());
    }

    pub inline fn getPML4TableUnchecked(specific: Specific) !*PML4Table {
        return try getPML4Table(specific.cr3);
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
        .x86 => @as(Pointer, @ptrFromInt(try lib.tryDereferenceAddress(virtual_address.value()))),
        else => virtual_address.access(Pointer),
    };
}

fn getPML4Table(cr3r: cr3) !*PML4Table {
    const pml4_table = try accessPageTable(cr3r.getAddress(), *PML4Table);
    return pml4_table;
}

fn getPDPTable(pml4_table: *PML4Table, indices: Indices, flags: MemoryFlags, maybe_page_allocator: ?PageAllocator) !*PDPTable {
    const index = indices[@intFromEnum(Level.PML4)];
    const entry_pointer = &pml4_table[index];

    const table_physical_address = physical_address_blk: {
        const entry_value = entry_pointer.*;
        if (entry_value.present) {
            const entry_address = unpackAddress(entry_value);
            break :physical_address_blk PhysicalAddress.new(entry_address);
        } else {
            if (maybe_page_allocator) |page_allocator| {
                const entry_allocation = try page_allocator.allocatePageTable(.{
                    .level = .PDP,
                    .user = flags.user,
                });

                entry_pointer.* = PML4TE{
                    .present = true,
                    .write = true,
                    .user = flags.user,
                    .address = packAddress(PML4TE, entry_allocation.address.value()),
                };

                break :physical_address_blk entry_allocation.address;
            } else {
                return Allocator.Allocate.Error.OutOfMemory;
            }
        }
    };

    return try accessPageTable(table_physical_address, *PDPTable);
}

pub inline fn getPageEntry(comptime Entry: type, physical_address: u64, flags: MemoryFlags) Entry {
    return if (@hasDecl(Entry, "page_size") and flags.page_size) Entry{
        .present = true,
        .write = flags.write,
        .user = flags.user,
        .page_level_cache_disable = flags.cache_disable,
        .global = flags.global,
        .pat = flags.pat,
        .address = packAddress(Entry, physical_address),
        .execute_disable = flags.execute_disable,
        .page_size = flags.page_size,
    } else Entry{
        .present = true,
        .write = flags.write,
        .user = flags.user,
        .page_level_cache_disable = flags.cache_disable,
        .global = flags.global,
        .pat = flags.pat,
        .address = packAddress(Entry, physical_address),
        .execute_disable = flags.execute_disable,
    };
}

fn mapPageTable1GB(pdp_table: *PDPTable, indices: Indices, physical_address: u64, flags: MemoryFlags) MapError!void {
    const entry_index = indices[@intFromEnum(Level.PDP)];
    const entry_pointer = &pdp_table[entry_index];

    if (entry_pointer.present) return MapError.already_present_1gb;

    assert(isAlignedGeneric(u64, physical_address, valid_page_sizes[2]));

    entry_pointer.* = @as(PDPTE, @bitCast(getPageEntry(PDPTE_1GB, physical_address, flags)));
}

fn mapPageTable2MB(pd_table: *PDTable, indices: Indices, physical_address: u64, flags: MemoryFlags) !void {
    const entry_index = indices[@intFromEnum(Level.PD)];
    const entry_pointer = &pd_table[entry_index];
    const entry_value = entry_pointer.*;

    if (entry_value.present) {
        log.err("Already mapped to: 0x{x}", .{unpackAddress(entry_value)});
        return MapError.already_present_2mb;
    }

    assert(isAlignedGeneric(u64, physical_address, valid_page_sizes[1]));

    entry_pointer.* = @as(PDTE, @bitCast(getPageEntry(PDTE_2MB, physical_address, flags)));
}

fn mapPageTable4KB(p_table: *PTable, indices: Indices, physical_address: u64, flags: MemoryFlags) !void {
    const entry_index = indices[@intFromEnum(Level.PT)];
    const entry_pointer = &p_table[entry_index];

    if (entry_pointer.present) {
        log.err("Trying to map to 0x{x}. Already mapped to 0x{x}", .{ physical_address, unpackAddress(entry_pointer.*) });
        return MapError.already_present_4kb;
    }

    assert(isAlignedGeneric(u64, physical_address, valid_page_sizes[0]));

    entry_pointer.* = @as(PTE, @bitCast(getPageEntry(PTE, physical_address, flags)));
}

const ToImplementError = error{
    page_size,
};

fn getPDTable(pdp_table: *PDPTable, indices: Indices, flags: MemoryFlags, page_allocator: PageAllocator) !*PDTable {
    const entry_index = indices[@intFromEnum(Level.PDP)];
    const entry_pointer = &pdp_table[entry_index];

    const table_physical_address = physical_address_blk: {
        const entry_value = entry_pointer.*;
        if (entry_value.present) {
            // The address is mapped with a 1GB page
            if (entry_value.page_size) {
                return ToImplementError.page_size;
            } else break :physical_address_blk PhysicalAddress.new(unpackAddress(entry_value));
        } else {
            const entry_allocation = try page_allocator.allocatePageTable(.{
                .level = .PD,
                .user = flags.user,
            });

            entry_pointer.* = PDPTE{
                .present = true,
                .write = true,
                .user = flags.user,
                .address = packAddress(PDPTE, entry_allocation.address.value()),
            };

            break :physical_address_blk entry_allocation.address;
        }
    };

    return try accessPageTable(table_physical_address, *PDTable);
}

fn getPTable(pd_table: *PDTable, indices: Indices, flags: MemoryFlags, page_allocator: PageAllocator) !*PTable {
    const entry_pointer = &pd_table[indices[@intFromEnum(Level.PD)]];
    const table_physical_address = physical_address_blk: {
        const entry_value = entry_pointer.*;
        if (entry_value.present) {
            // The address is mapped with a 2MB page
            if (entry_value.page_size) {
                return ToImplementError.page_size;
            } else break :physical_address_blk PhysicalAddress.new(unpackAddress(entry_value));
        } else {
            const entry_allocation = try page_allocator.allocatePageTable(.{ .level = .PT, .user = flags.user });

            entry_pointer.* = PDTE{
                .present = true,
                .write = true,
                .user = flags.user,
                .address = packAddress(PDTE, entry_allocation.address.value()),
            };

            break :physical_address_blk entry_allocation.address;
        }
    };

    return try accessPageTable(table_physical_address, *PTable);
}

const half_entry_count = (@sizeOf(PML4Table) / @sizeOf(PML4TE)) / 2;

const needed_physical_memory_for_bootstrapping_cpu_driver_address_space = @sizeOf(PML4Table) + @sizeOf(PDPTable) * 256;

pub fn computeIndices(virtual_address: u64) Indices {
    var indices: Indices = undefined;
    var va = virtual_address;
    va = va >> 12;
    indices[3] = @as(u9, @truncate(va));
    va = va >> 9;
    indices[2] = @as(u9, @truncate(va));
    va = va >> 9;
    indices[1] = @as(u9, @truncate(va));
    va = va >> 9;
    indices[0] = @as(u9, @truncate(va));

    return indices;
}

pub inline fn newFlags(general_flags: Mapping.Flags) MemoryFlags {
    return MemoryFlags{
        .write = general_flags.write,
        .user = general_flags.user,
        .cache_disable = general_flags.cache_disable,
        .global = general_flags.global,
        .execute_disable = !general_flags.execute,
    };
}

pub const MemoryFlags = packed struct(u64) {
    present: bool = true,
    write: bool = false,
    user: bool = false,
    write_through: bool = false,
    cache_disable: bool = false,
    dirty: bool = false,
    global: bool = false,
    pat: bool = false,
    page_size: bool = false,
    reserved: u54 = 0,
    execute_disable: bool = false,

    comptime {
        assert(@sizeOf(u64) == @sizeOf(MemoryFlags));
    }
};

const address_mask: u64 = 0x0000_00ff_ffff_f000;

pub const Level = Level4;

pub const Level4 = enum(u2) {
    PML4 = 0,
    PDP = 1,
    PD = 2,
    PT = 3,

    pub const count = lib.enumCount(@This());
};

pub const Level5 = enum(u3) {};

pub fn EntryTypeMapSize(comptime page_size: comptime_int) usize {
    return switch (Level) {
        Level4 => switch (page_size) {
            lib.arch.valid_page_sizes[0] => 4,
            lib.arch.valid_page_sizes[1] => 3,
            lib.arch.valid_page_sizes[2] => 2,
            else => @compileError("Unknown page size"),
        },
        Level5 => @compileError("TODO"),
        else => @compileError("unreachable"),
    };
}

pub fn EntryTypeMap(comptime page_size: comptime_int) [EntryTypeMapSize(page_size)]type {
    const map_size = EntryTypeMapSize(page_size);
    const Result = [map_size]type;
    var result: Result = undefined;
    switch (Level) {
        Level4, Level5 => {
            if (@hasField(Level, "pml5")) {
                @compileError("TODO: type_map[@enumToInt(Level.PML5)] =");
            }

            result[@intFromEnum(Level.PML4)] = PML4TE;

            if (page_size == lib.arch.valid_page_sizes[2]) {
                assert(map_size == 2 + @intFromBool(Level == Level5));
                result[@intFromEnum(Level.PDP)] = PDPTE_1GB;
            } else {
                result[@intFromEnum(Level.PDP)] = PDPTE;

                if (page_size == lib.arch.valid_page_sizes[1]) {
                    assert(map_size == @as(usize, 3) + @intFromBool(Level == Level5));
                    result[@intFromEnum(Level.PD)] = PDTE_2MB;
                } else {
                    assert(page_size == lib.arch.valid_page_sizes[0]);

                    result[@intFromEnum(Level.PD)] = PDTE;
                    result[@intFromEnum(Level.PT)] = PTE;
                }
            }
        },
        else => @compileError("Unexpected level type"),
    }

    return result;
}

pub inline fn unpackAddress(entry: anytype) u64 {
    const T = @TypeOf(entry);
    const RealType = switch (@typeInfo(T)) {
        .Pointer => |pointer| pointer.child,
        else => T,
    };
    const address_offset = @bitOffsetOf(RealType, "address");
    return @as(u64, entry.address) << address_offset;
}

fn AddressType(comptime T: type) type {
    var a: T = undefined;
    return @TypeOf(@field(a, "address"));
}

pub fn packAddress(comptime T: type, physical_address: u64) AddressType(T) {
    assert(physical_address < lib.config.cpu_driver_higher_half_address);
    const address_offset = @bitOffsetOf(T, "address");
    return @as(AddressType(T), @intCast(physical_address >> address_offset));
}

pub const PML4TE = packed struct(u64) {
    present: bool = false,
    write: bool = false,
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

pub const PDPTE = packed struct(u64) {
    present: bool = false,
    write: bool = false,
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

pub const PDPTE_1GB = packed struct(u64) {
    present: bool = false,
    write: bool = false,
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

pub const PDTE = packed struct(u64) {
    present: bool = false,
    write: bool = false,
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

pub const PDTE_2MB = packed struct(u64) {
    present: bool = false,
    write: bool = false,
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

pub const PTE = packed struct(u64) {
    present: bool = false,
    write: bool = false,
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

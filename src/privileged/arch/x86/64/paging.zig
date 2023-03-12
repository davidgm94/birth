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
const PhysicalAddress = x86_64.PhysicalAddress;
const VirtualAddress = x86_64.VirtualAddress;
const PhysicalMemoryRegion = x86_64.PhysicalMemoryRegion;
const VirtualMemoryRegion = x86_64.VirtualMemoryRegion;
const PhysicalAddressSpace = x86_64.PhysicalAddressSpace;
const VirtualAddressSpace = x86_64.VirtualAddressSpace;

pub const Specific = extern struct {
    cr3: cr3 align(@sizeOf(u64)) = undefined,
};

const Indices = [enumCount(PageIndex)]u16;

const MapError = error{
    already_present_4kb,
    already_present_2mb,
    already_present_1gb,
    validation_failed,
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

pub fn map(virtual_address_space: *VirtualAddressSpace, asked_physical_address: u64, asked_virtual_address: u64, size: u64, flags: MemoryFlags) !void {
    const top_virtual_address = asked_virtual_address + size;

    inline for (reverse_valid_page_sizes, 0..) |reverse_page_size, reverse_page_index| {
        if (size >= reverse_page_size) {
            const is_smallest_page_size = reverse_page_index == reverse_valid_page_sizes.len - 1;

            if (is_smallest_page_size) {
                var virtual_address = asked_virtual_address;
                var physical_address = asked_physical_address;

                while (virtual_address < top_virtual_address) : ({
                    physical_address += reverse_page_size;
                    virtual_address += reverse_page_size;
                }) {
                    try map4KPage(virtual_address_space, physical_address, virtual_address, flags);
                }

                return;
            } else {
                const aligned_page_address = alignForwardGeneric(u64, asked_virtual_address, reverse_page_size);
                const prologue_misalignment = aligned_page_address - asked_virtual_address;
                const aligned_size_left = size - prologue_misalignment;

                if (aligned_size_left >= reverse_page_size) {
                    if (prologue_misalignment != 0) {
                        try map(virtual_address_space, asked_physical_address, asked_virtual_address, prologue_misalignment, flags);
                    }

                    const virtual_address = aligned_page_address;
                    const physical_address = asked_physical_address + prologue_misalignment;
                    const this_page_top_physical_address = alignBackwardGeneric(u64, physical_address + aligned_size_left, reverse_page_size);
                    const this_page_top_virtual_address = alignBackwardGeneric(u64, virtual_address + aligned_size_left, reverse_page_size);
                    const this_huge_page_size = this_page_top_virtual_address - virtual_address;
                    try mapGeneric(virtual_address_space, physical_address, virtual_address, this_huge_page_size, reverse_page_size, flags);

                    const epilogue_misalignment = top_virtual_address - this_page_top_virtual_address;

                    if (epilogue_misalignment != 0) {
                        const epilogue_physical_address = this_page_top_physical_address;
                        const epilogue_virtual_address = this_page_top_virtual_address;

                        try map(virtual_address_space, epilogue_physical_address, epilogue_virtual_address, epilogue_misalignment, flags);
                    }

                    return;
                }
            }
        }
    }

    @panic("Some mapping did not go well");
}

fn mapGeneric(virtual_address_space: *VirtualAddressSpace, asked_physical_address: u64, asked_virtual_address: u64, size: u64, comptime asked_page_size: comptime_int, flags: MemoryFlags) !void {
    const reverse_index = switch (asked_page_size) {
        reverse_valid_page_sizes[0] => 0,
        reverse_valid_page_sizes[1] => 1,
        reverse_valid_page_sizes[2] => 2,
        else => @compileError("Invalid page size"),
    };
    _ = reverse_index;

    if (true) {
        if (!isAlignedGeneric(u64, asked_physical_address, asked_page_size)) {
            log.debug("PA: {}. Page size: 0x{x}", .{ asked_physical_address, asked_page_size });
            @panic("Misaligned physical address in mapGeneric");
        }
        if (!isAlignedGeneric(u64, asked_virtual_address, asked_page_size)) {
            @panic("Misaligned virtual address in mapGeneric");
        }
        if (!isAlignedGeneric(u64, size, asked_page_size)) {
            //log.debug("Asked size: 0x{x}. Asked page size: 0x{x}", .{ size, asked_page_size });
            @panic("Misaligned size in mapGeneric");
        }
    } else {
        assert(isAligned(asked_physical_address, asked_page_size));
        assert(isAligned(asked_virtual_address, asked_page_size));
        assert(isAligned(size, asked_page_size));
    }

    var virtual_address = asked_virtual_address;
    var physical_address = asked_physical_address;
    const top_virtual_address = asked_virtual_address + size;

    // TODO: batch better
    switch (asked_page_size) {
        // 1 GB
        0x1000 * 0x200 * 0x200 => {
            while (virtual_address < top_virtual_address) : ({
                physical_address += asked_page_size;
                virtual_address += asked_page_size;
            }) {
                try map1GBPage(virtual_address_space, physical_address, virtual_address, flags);
            }
        },
        // 2 MB
        0x1000 * 0x200 => {
            while (virtual_address < top_virtual_address) : ({
                physical_address += asked_page_size;
                virtual_address += asked_page_size;
            }) {
                try map2MBPage(virtual_address_space, physical_address, virtual_address, flags);
            }
        },
        // Smallest: 4 KB
        0x1000 => {
            while (virtual_address < top_virtual_address) : ({
                physical_address += asked_page_size;
                virtual_address += asked_page_size;
            }) {
                try map4KPage(virtual_address_space, physical_address, virtual_address, flags);
            }
        },
        else => @compileError("Invalid reverse valid page size"),
    }
}

fn map1GBPage(virtual_address_space: *VirtualAddressSpace, physical_address: u64, virtual_address: u64, flags: MemoryFlags) !void {
    const indices = computeIndices(virtual_address);

    const pml4_table = getPML4Table(virtual_address_space.arch.cr3) catch privileged.panic("[1G] PML4 access failed when mapping 0x{x} -> 0x{x}", .{ virtual_address, physical_address });
    const pdp_table = getPDPTable(virtual_address_space, pml4_table, indices, flags) catch privileged.panic("[1G] PDP table access failed when mapping 0x{x} -> 0x{x}", .{ virtual_address, physical_address });

    try mapPageTable1GB(pdp_table, indices, physical_address, flags);

    const translated_physical_address = translateAddress(virtual_address_space, VirtualAddress(.local).new(virtual_address)) catch |err| {
        log.err("Error when mapping 1GB page (0x{x} -> 0x{x}): {}", .{ virtual_address, physical_address, err });
        return MapError.validation_failed;
    };

    if (physical_address != translated_physical_address.value()) {
        log.err("Given: 0x{x}. Have: 0x{x}", .{ physical_address, translated_physical_address.value() });
        return MapError.validation_failed;
    }
}

fn map2MBPage(virtual_address_space: *VirtualAddressSpace, physical_address: u64, virtual_address: u64, flags: MemoryFlags) !void {
    const indices = computeIndices(virtual_address);

    const pml4_table = getPML4Table(virtual_address_space.arch.cr3) catch privileged.panic("[2M] PML4 access failed when mapping 0x{x} -> 0x{x}", .{ virtual_address, physical_address });
    const pdp_table = getPDPTable(virtual_address_space, pml4_table, indices, flags) catch privileged.panic("[2M] PDP table access failed when mapping 0x{x} -> 0x{x}", .{ virtual_address, physical_address });
    const pd_table = getPDTable(virtual_address_space, pdp_table, indices, flags) catch privileged.panic("[2M] PD table access failed when mapping 0x{x} -> 0x{x}", .{ virtual_address, physical_address });

    try mapPageTable2MB(pd_table, indices, physical_address, flags);

    const translated_physical_address = translateAddress(virtual_address_space, VirtualAddress(.local).new(virtual_address)) catch |err| {
        log.err("Error when mapping 2MB page (0x{x} -> 0x{x}): {}", .{ virtual_address, physical_address, err });
        return MapError.validation_failed;
    };

    if (physical_address != translated_physical_address.value()) {
        log.err("Given: 0x{x}. Have: 0x{x}", .{ physical_address, translated_physical_address.value() });
        return MapError.validation_failed;
    }
}

fn map4KPage(virtual_address_space: *VirtualAddressSpace, physical_address: u64, virtual_address: u64, flags: MemoryFlags) MapError!void {
    const indices = computeIndices(virtual_address);

    // if (virtual_address >= 0xffff_ffff_8000_0000) log.debug("Before PML4", .{});
    const pml4_table = getPML4Table(virtual_address_space.arch.cr3) catch privileged.panic("[4K] PML4 access failed when mapping 0x{x} -> 0x{x}", .{ virtual_address, physical_address });
    // if (virtual_address >= 0xffff_ffff_8000_0000) log.debug("PML4Table: 0x{x}", .{@ptrToInt(pml4_table)});
    const pdp_table = getPDPTable(virtual_address_space, pml4_table, indices, flags) catch privileged.panic("[4K] PDP table access failed when mapping 0x{x} -> 0x{x}", .{ virtual_address, physical_address });
    // if (virtual_address >= 0xffff_ffff_8000_0000)
    // log.debug("PDP table: 0x{x}", .{@ptrToInt(pdp_table)});
    const pd_table = getPDTable(virtual_address_space, pdp_table, indices, flags) catch privileged.panic("[4K] PD table access failed when mapping 0x{x} -> 0x{x}", .{ virtual_address, physical_address });
    // if (virtual_address >= 0xffff_ffff_8000_0000)
    // log.debug("PD table: 0x{x}", .{@ptrToInt(pd_table)});
    const p_table = getPTable(virtual_address_space, pd_table, indices, flags) catch privileged.panic("[4K] P table access failed when mapping 0x{x} -> 0x{x}", .{ virtual_address, physical_address });
    // if (virtual_address >= 0xffff_ffff_8000_0000)
    // log.debug("P table: 0x{x}", .{@ptrToInt(p_table)});

    try mapPageTable4KB(p_table, indices, physical_address, flags);

    const translated_physical_address = translateAddress(virtual_address_space, VirtualAddress(.local).new(virtual_address)) catch |err| {
        log.err("Error when mapping 4KB page (0x{x} -> 0x{x}): {}", .{ virtual_address, physical_address, err });
        return MapError.validation_failed;
    };

    if (physical_address != translated_physical_address.value()) {
        log.err("Given: 0x{x}. Have: 0x{x}", .{ physical_address, translated_physical_address.value() });
        return MapError.validation_failed;
    }
}
pub fn accessPageTable(physical_address: PhysicalAddress(.local), comptime Pointer: type) !Pointer {
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
    return try accessPageTable(cr3r.getAddress(), *volatile PML4Table);
}

fn getPDPTable(virtual_address_space: *VirtualAddressSpace, pml4_table: *volatile PML4Table, indices: Indices, flags: MemoryFlags) !*volatile PDPTable {
    const index = indices[@enumToInt(PageIndex.PML4)];
    const entry_pointer = &pml4_table[index];

    const table_physical_address = physical_address_blk: {
        const entry_value = entry_pointer.*;
        if (entry_value.present) {
            const entry_address = unpackAddress(entry_value);
            break :physical_address_blk PhysicalAddress(.local).new(entry_address);
        } else {
            // TODO: track this physical allocation in order to map it later in the kernel address space
            const entry_allocation = virtual_address_space.allocatePageTables(@sizeOf(PDPTable), 0x1000) catch @panic("PDP table allocation");

            entry_pointer.* = PML4TE{
                .present = true,
                .read_write = true,
                .user = flags.user,
                .address = packAddress(PML4TE, entry_allocation.address.value()),
            };

            break :physical_address_blk entry_allocation.address;
        }
    };

    return try accessPageTable(table_physical_address, *volatile PDPTable);
}

fn getPageEntry(comptime Entry: type, physical_address: u64, flags: MemoryFlags) Entry {
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
    const entry_index = indices[@enumToInt(PageIndex.PDP)];
    const entry_pointer = &pdp_table[entry_index];

    if (entry_pointer.present) return MapError.already_present_1gb;

    assert(isAlignedGeneric(u64, physical_address, valid_page_sizes[2]));

    entry_pointer.* = @bitCast(PDPTE, getPageEntry(PDPTE_1GB, physical_address, flags));
}

fn mapPageTable2MB(pd_table: *volatile PDTable, indices: Indices, physical_address: u64, flags: MemoryFlags) !void {
    const entry_index = indices[@enumToInt(PageIndex.PD)];
    const entry_pointer = &pd_table[entry_index];
    const entry_value = entry_pointer.*;

    if (entry_value.present) return MapError.already_present_2mb;

    assert(isAlignedGeneric(u64, physical_address, valid_page_sizes[1]));

    entry_pointer.* = @bitCast(PDTE, getPageEntry(PDTE_2MB, physical_address, flags));
}

fn mapPageTable4KB(p_table: *volatile PTable, indices: Indices, physical_address: u64, flags: MemoryFlags) !void {
    const entry_index = indices[@enumToInt(PageIndex.PT)];
    const entry_pointer = &p_table[entry_index];

    if (entry_pointer.present) {
        log.err("PTable address: 0x{x}, entry_index: {}, entry_pointer: 0x{x}", .{ @ptrToInt(p_table), entry_index, @ptrToInt(entry_pointer) });
        return MapError.already_present_4kb;
    }

    assert(isAlignedGeneric(u64, physical_address, valid_page_sizes[0]));

    entry_pointer.* = @bitCast(PTE, getPageEntry(PTE, physical_address, flags));
}

fn getPDTable(virtual_address_space: *VirtualAddressSpace, pdp_table: *volatile PDPTable, indices: Indices, flags: MemoryFlags) !*volatile PDTable {
    const entry_index = indices[@enumToInt(PageIndex.PDP)];
    const entry_pointer = &pdp_table[entry_index];

    const table_physical_address = physical_address_blk: {
        const entry_value = entry_pointer.*;
        if (entry_value.present) {
            // The address is mapped with a 1GB page
            if (entry_value.page_size) {
                @panic("todo pd table page size");
            }
            break :physical_address_blk PhysicalAddress(.local).new(unpackAddress(entry_value));
        } else {
            // TODO: track this physical allocation in order to map it later in the kernel address space
            const entry_allocation = virtual_address_space.allocatePageTables(@sizeOf(PDTable), 0x1000) catch @panic("getPDTable");

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

fn getPTable(virtual_address_space: *VirtualAddressSpace, pd_table: *volatile PDTable, indices: Indices, flags: MemoryFlags) !*volatile PTable {
    const entry_pointer = &pd_table[indices[@enumToInt(PageIndex.PD)]];
    const table_physical_address = physical_address_blk: {
        const entry_value = entry_pointer.*;
        if (entry_value.present) {
            // The address is mapped with a 2MB page
            if (entry_value.page_size) {
                @panic("todo ptable page size");
            }
            break :physical_address_blk PhysicalAddress(.local).new(unpackAddress(entry_value));
        } else {
            const entry_allocation = virtual_address_space.allocatePageTables(@sizeOf(PTable), 0x1000) catch @panic("getPTable allocation failed");

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

pub fn initKernelBSP(page_allocator: *Allocator) !VirtualAddressSpace {
    var virtual_address_space = VirtualAddressSpace{
        .arch = undefined,
        .options = .{
            .user = false,
            .mapped_page_tables = true,
            .log_pages = false,
        },
        .backing_allocator = page_allocator,
    };

    const allocation_result = try virtual_address_space.allocatePageTables(needed_physical_memory_for_bootstrapping_cpu_driver_address_space, lib.arch.valid_page_sizes[0]);
    const pml4_physical_region = allocation_result.takeSlice(@sizeOf(PML4Table));
    const pdp_physical_region = allocation_result.offset(@sizeOf(PML4Table));

    //log.debug("PML4", .{});
    const pml4_entries = try accessPageTable(pml4_physical_region.address, *volatile PML4Table);

    for (pml4_entries[0..half_entry_count]) |*entry| {
        entry.* = @bitCast(PML4TE, @as(u64, 0));
    }

    //log.debug("PML4 entries", .{});
    for (pml4_entries[half_entry_count..], 0..) |*entry, i| {
        entry.* = PML4TE{
            .present = true,
            .read_write = true,
            .address = packAddress(PML4TE, pdp_physical_region.offset(i * @sizeOf(PDPTable)).address.value()),
        };
    }

    virtual_address_space.arch = .{
        .cr3 = cr3.from_address(pml4_physical_region.address),
    };

    return virtual_address_space;
}

pub inline fn makeCurrent(virtual_address_space: *const VirtualAddressSpace) void {
    virtual_address_space.arch.cr3.write();
}

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

pub inline fn newFlags(general_flags: VirtualAddressSpace.Flags, comptime core_locality: privileged.CoreLocality) MemoryFlags {
    return MemoryFlags{
        .read_write = general_flags.write,
        .user = general_flags.user,
        .cache_disable = general_flags.cache_disable,
        .global = switch (core_locality) {
            .global => true,
            .local => false,
        },
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

pub const PML4Table = [512]PML4TE;
pub const PDPTable = [512]PDPTE;
pub const PDTable = [512]PDTE;
pub const PTable = [512]PTE;

pub fn translateAddress(virtual_address_space: *VirtualAddressSpace, virtual_address: VirtualAddress(.local)) TranslateError!PhysicalAddress(.local) {
    const indices = computeIndices(virtual_address.value());

    const pml4_table = getPML4Table(virtual_address_space.arch.cr3) catch privileged.panic("[translateAddress] PML4 access failed when translating 0x{x}", .{virtual_address.value()});
    const pml4_entry = pml4_table[indices[@enumToInt(PageIndex.PML4)]];
    if (!pml4_entry.present) {
        return TranslateError.pml4_entry_not_present;
    }

    const pml4_entry_address = PhysicalAddress(.local).new(unpackAddress(pml4_entry));
    if (pml4_entry_address.value() == 0) {
        return TranslateError.pml4_entry_address_null;
    }

    const pdp_table = getPDPTable(virtual_address_space, pml4_table, indices, undefined) catch privileged.panic("[translateAddress] PDP access failed when translating 0x{x}", .{virtual_address.value()});
    const pdp_entry = &pdp_table[indices[@enumToInt(PageIndex.PDP)]];
    if (!pdp_entry.present) {
        return TranslateError.pdp_entry_not_present;
    }

    if (pdp_entry.page_size) {
        const pdp_entry_1gb = @bitCast(PDPTE_1GB, pdp_entry.*);
        const entry_address_value = unpackAddress(pdp_entry_1gb);
        const physical_address = PhysicalAddress(.local).new(entry_address_value);
        if (lib.isAlignedGeneric(u64, virtual_address.value(), lib.gb)) {
            return physical_address;
        } else {
            @panic("unaligned 1gb");
        }
    }

    const pdp_entry_address = PhysicalAddress(.local).new(unpackAddress(pdp_entry.*));
    if (pdp_entry_address.value() == 0) {
        return TranslateError.pdp_entry_address_null;
    }

    const pd_table = accessPageTable(pdp_entry_address, *volatile PDTable) catch {
        privileged.panic("[translateAddress] PD access failed when translating 0x{x}. Tried to access page at physical address: 0x{x}. Written in 0x{x}", .{ virtual_address.value(), pdp_entry_address.value(), @ptrToInt(pdp_entry) });
    };
    const pd_entry = pd_table[indices[@enumToInt(PageIndex.PD)]];
    if (!pd_entry.present) {
        return TranslateError.pd_entry_not_present;
    }

    if (pd_entry.page_size) {
        const pd_entry_2mb = @bitCast(PDTE_2MB, pd_entry);
        const entry_address_value = unpackAddress(pd_entry_2mb);
        const physical_address = PhysicalAddress(.local).new(entry_address_value);
        if (lib.isAlignedGeneric(u64, virtual_address.value(), 2 * lib.mb)) {
            return physical_address;
        } else {
            @panic("unaligned 2mb");
        }
    }

    const pd_entry_address = PhysicalAddress(.local).new(unpackAddress(pd_entry));
    if (pd_entry_address.value() == 0) {
        return TranslateError.pd_entry_address_null;
    }

    const p_table = accessPageTable(pd_entry_address, *volatile PTable) catch privileged.panic("[translateAddress] PD access failed when translating 0x{x}", .{virtual_address.value()});
    const pt_entry = p_table[indices[@enumToInt(PageIndex.PT)]];
    if (!pt_entry.present) {
        return TranslateError.pt_entry_not_present;
    }

    const pt_entry_address = PhysicalAddress(.local).new(unpackAddress(pt_entry));
    if (pt_entry_address.value() == 0) {
        return TranslateError.pt_entry_address_null;
    }

    return pt_entry_address;
}

pub fn setMappingFlags(virtual_address_space: *VirtualAddressSpace, virtual_address: u64, flags: VirtualAddressSpace.Flags) !void {
    const indices = computeIndices(virtual_address);

    const vas_cr3 = virtual_address_space.arch.cr3;
    log.debug("CR3: {}", .{vas_cr3});

    const pml4_physical_address = vas_cr3.getAddress();
    log.debug("PML4: 0x{x}", .{pml4_physical_address.value()});

    const pml4_table = try accessPageTable(pml4_physical_address, *volatile PML4Table);
    const pml4_entry = pml4_table[indices[@enumToInt(PageIndex.PML4)]];
    if (!pml4_entry.present) {
        return TranslateError.pml4_entry_not_present;
    }

    const pml4_entry_address = PhysicalAddress(.local).new(unpackAddress(pml4_entry));
    if (pml4_entry_address.value() == 0) {
        return TranslateError.pml4_entry_address_null;
    }

    const pdp_table = try accessPageTable(pml4_entry_address, *volatile PDPTable);
    const pdp_entry = pdp_table[indices[@enumToInt(PageIndex.PDP)]];
    if (!pdp_entry.present) {
        return TranslateError.pdp_entry_not_present;
    }

    const pdp_entry_address = PhysicalAddress(.local).new(unpackAddress(pdp_entry));
    if (pdp_entry_address.value() == 0) {
        return TranslateError.pdp_entry_address_null;
    }

    const pd_table = try accessPageTable(pdp_entry_address, *volatile PDTable);
    const pd_entry = pd_table[indices[@enumToInt(PageIndex.PD)]];
    if (!pd_entry.present) {
        return TranslateError.pd_entry_not_present;
    }

    const pd_entry_address = PhysicalAddress(.local).new(unpackAddress(pd_entry));
    if (pd_entry_address.value() == 0) {
        return TranslateError.pd_entry_address_null;
    }

    const pt_table = try accessPageTable(pd_entry_address, *volatile PTable);
    const pt_entry = &pt_table[indices[@enumToInt(PageIndex.PT)]];
    if (!pt_entry.present) {
        return TranslateError.pd_entry_not_present;
    }

    pt_entry.read_write = flags.write;
    pt_entry.user = flags.user;
    pt_entry.page_level_cache_disable = flags.cache_disable;
    pt_entry.global = flags.global;
    pt_entry.execute_disable = !flags.execute;
}

pub inline fn copyHigherHalf(pml4_physical_address: PhysicalAddress(.local)) void {
    log.debug("Higher half", .{});
    const cpu_side_pml4_table = pml4_physical_address.toHigherHalfVirtualAddress().access(*PML4Table);
    const privileged_cpu_pml4_table = try getPML4Table(cr3.read());
    for (cpu_side_pml4_table[0x100..], privileged_cpu_pml4_table[0x100..]) |*pml4_entry, cpu_pml4_entry| {
        pml4_entry.* = cpu_pml4_entry;
    }
}

pub fn contextSwitch(virtual_address_space: *VirtualAddressSpace) void {
    assert(virtual_address_space.options.mapped_page_tables);
    log.debug("Setting new address space: {}", .{virtual_address_space.arch.cr3});
    virtual_address_space.arch.cr3.write();
}

pub fn validate(virtual_address_space: *VirtualAddressSpace) !void {
    const pml4_table_physical_address = virtual_address_space.arch.cr3.getAddress();
    try makeSurePageIsMapped(virtual_address_space, pml4_table_physical_address);
    @panic("TODO: validate");
}

const MakeSureError = error{
    translate_identity,
    translate_higher_half,
};

fn makeSurePageIsMapped(virtual_address_space: *VirtualAddressSpace, physical_address: PhysicalAddress(.local)) !void {
    const translated_identity_physical_address = try virtual_address_space.translateAddress(physical_address.toIdentityMappedVirtualAddress());
    if (translated_identity_physical_address.value() != physical_address.value()) {
        return MakeSureError.translate_identity;
    }
    const translated_higher_half_physical_address = try virtual_address_space.translateAddress(physical_address.toHigherHalfVirtualAddress());
    if (translated_higher_half_physical_address.value() != physical_address.value()) {
        return MakeSureError.translate_higher_half;
    }
}

pub inline fn switchTo(virtual_address_space: *VirtualAddressSpace, execution_mode: lib.TraditionalExecutionMode) void {
    const mask = ~@as(u64, 1 << 12);
    const masked_cr3 = (@bitCast(u64, virtual_address_space.arch.cr3) & mask);
    const privileged_or = (@as(u64, @enumToInt(execution_mode)) << 12);
    const new_cr3 = @bitCast(cr3, masked_cr3 | privileged_or);
    log.debug("Execution mode: {s}. CR3: 0x{x}. Mask: 0x{x}. Masked CR3: 0x{x}. Privileged OR: 0x{x}. New CR3: 0x{x}", .{ @tagName(execution_mode), @bitCast(u64, virtual_address_space.arch.cr3), mask, masked_cr3, privileged_or, @bitCast(u64, new_cr3) });
    virtual_address_space.arch.cr3 = new_cr3;
}

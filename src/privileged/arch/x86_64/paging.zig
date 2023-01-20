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
const panic = privileged.panic;
const PhysicalAddress = privileged.GenericPhysicalAddress(.x86_64);
const PhysicalAddressSpace = privileged.PhysicalAddressSpace;
const VirtualAddress = privileged.GenericVirtualAddress(.x86_64);
const VirtualAddressSpace = privileged.GenericVirtualAddressSpace(.x86_64);
const TranslationResult = VirtualAddressSpace.TranslationResult;

const arch = lib.arch.x86_64;
const valid_page_sizes = arch.valid_page_sizes;
const reverse_valid_page_sizes = arch.reverse_valid_page_sizes;

const cr3 = privileged.arch.x86_64.registers.cr3;

const higher_half_entry_index = 512 / 2;

pub const Specific = extern struct {
    cr3: cr3 = undefined,

    pub fn format(specific: Specific, comptime _: []const u8, _: lib.InternalFormatOptions, writer: anytype) @TypeOf(writer).Error!void {
        try lib.internal_format(writer, "{}", .{specific.cr3});
    }
};

const Indices = [enumCount(PageIndex)]u16;

//const limine_physical_allocator = CustomAllocator{};

fn map_function(vas_cr3: cr3, asked_physical_address: u64, asked_virtual_address: u64, size: u64, flags: MemoryFlags, physical_allocator: *Allocator) !void {
    if (size == valid_page_sizes[0]) {
        try map_4k_page(vas_cr3, asked_physical_address, asked_virtual_address, flags, physical_allocator);
    } else {
        const top_virtual_address = asked_virtual_address + size;

        inline for (reverse_valid_page_sizes) |reverse_page_size, reverse_page_index| {
            if (size >= reverse_page_size) {
                const is_smallest_page_size = reverse_page_index == reverse_valid_page_sizes.len - 1;

                if (is_smallest_page_size) {
                    var virtual_address = asked_virtual_address;
                    var physical_address = asked_physical_address;

                    while (virtual_address < top_virtual_address) : ({
                        physical_address += reverse_page_size;
                        virtual_address += reverse_page_size;
                    }) {
                        try map_4k_page(vas_cr3, physical_address, virtual_address, flags, physical_allocator);
                    }

                    break;
                } else {
                    const aligned_page_address = alignForwardGeneric(u64, asked_virtual_address, reverse_page_size);
                    const prologue_misalignment = aligned_page_address - asked_virtual_address;
                    const aligned_size_left = size - prologue_misalignment;

                    if (aligned_size_left >= reverse_page_size) {
                        if (prologue_misalignment != 0) {
                            try map_function(vas_cr3, asked_physical_address, asked_virtual_address, prologue_misalignment, flags, physical_allocator);
                        }

                        const virtual_address = aligned_page_address;
                        const physical_address = asked_physical_address + prologue_misalignment;
                        const this_page_top_physical_address = alignBackwardGeneric(u64, physical_address + aligned_size_left, reverse_page_size);
                        const this_page_top_virtual_address = alignBackwardGeneric(u64, virtual_address + aligned_size_left, reverse_page_size);
                        const this_huge_page_size = this_page_top_virtual_address - virtual_address;
                        try map_generic(vas_cr3, physical_address, virtual_address, this_huge_page_size, reverse_page_size, flags, physical_allocator);

                        const epilogue_misalignment = top_virtual_address - this_page_top_virtual_address;

                        if (epilogue_misalignment != 0) {
                            const epilogue_physical_address = this_page_top_physical_address;
                            const epilogue_virtual_address = this_page_top_virtual_address;

                            try map_function(vas_cr3, epilogue_physical_address, epilogue_virtual_address, epilogue_misalignment, flags, physical_allocator);
                        }

                        break;
                    } else {
                        try map_generic(vas_cr3, asked_physical_address, asked_virtual_address, size, reverse_valid_page_sizes[reverse_page_index + 1], flags, physical_allocator);
                        @panic("else taken");
                    }
                }
            }
        }
    }
}

const Error = error {
    invalid_physical,
    invalid_virtual,
    invalid_size,
    unaligned_physical,
    unaligned_virtual,
    unaligned_size,
};

pub fn bootstrap_map(virtual_address_space: *VirtualAddressSpace, comptime locality: privileged.CoreLocality, asked_physical_address: PhysicalAddress(locality), asked_virtual_address: VirtualAddress(locality), size: u64, general_flags: VirtualAddressSpace.Flags, physical_allocator: *Allocator) !void {
    // TODO: use flags
    const flags = general_flags.toArchitectureSpecific(locality);
    const vas_cr3 = virtual_address_space.arch.cr3;

    // if (!asked_physical_address.isValid()) return Error.invalid_physical;
    // if (!asked_virtual_address.isValid()) return Error.invalid_virtual;
    if (size == 0) {
        return Error.invalid_size;
    }
    if (!isAlignedGeneric(u64, asked_physical_address.value(), valid_page_sizes[0])) {
        return Error.unaligned_physical;
    }
    if (!isAlignedGeneric(u64, asked_virtual_address.value(), valid_page_sizes[0])) {
        return Error.unaligned_virtual;
    }
    if (!isAlignedGeneric(u64, size, valid_page_sizes[0])) {
        return Error.unaligned_size;
    }

    try map_function(vas_cr3, asked_physical_address.value(), asked_virtual_address.value(), size, flags, physical_allocator);
}

pub fn map_current(asked_physical_address: u64, asked_virtual_address: u64, size: u64, general_flags: VirtualAddressSpace.Flags, physical_allocator: *Allocator) !void {
    const flags = general_flags.toArchitectureSpecific(.global);
    const vas_cr3 = cr3.read();

    // TODO: figure out page size better
    try map_generic(vas_cr3, asked_physical_address, asked_virtual_address, size, valid_page_sizes[0], flags, physical_allocator);
}

pub fn context_switch(vas_cr3_int: u64) void {
    const vas_cr3 = @bitCast(cr3, vas_cr3_int);
    vas_cr3.write();
}

fn map_generic(vas_cr3: cr3, asked_physical_address: u64, asked_virtual_address: u64, size: u64, comptime asked_page_size: comptime_int, flags: MemoryFlags, physical_allocator: *Allocator) !void {
    const reverse_index = switch (asked_page_size) {
        reverse_valid_page_sizes[0] => 0,
        reverse_valid_page_sizes[1] => 1,
        reverse_valid_page_sizes[2] => 2,
        else => @compileError("Invalid page size"),
    };
    _ = reverse_index;

    if (true) {
        if (!isAlignedGeneric(u64, asked_physical_address, asked_page_size)) {
            //log.debug("PA: {}. Page size: 0x{x}", .{ asked_physical_address, asked_page_size });
            @panic("Misalignment");
        }
        if (!isAlignedGeneric(u64, asked_virtual_address, asked_page_size)) {
            @panic("wtf 2");
        }
        if (!isAlignedGeneric(u64, size, asked_page_size)) {
            //log.debug("Asked size: 0x{x}. Asked page size: 0x{x}", .{ size, asked_page_size });
            @panic("wtf 3");
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
                try map_1gb_page(vas_cr3, physical_address, virtual_address, flags, physical_allocator);
            }
        },
        // 2 MB
        0x1000 * 0x200 => {
            while (virtual_address < top_virtual_address) : ({
                physical_address += asked_page_size;
                virtual_address += asked_page_size;
            }) {
                try map_2mb_page(vas_cr3, physical_address, virtual_address, flags, physical_allocator);
            }
        },
        // Smallest: 4 KB
        0x1000 => {
            while (virtual_address < top_virtual_address) : ({
                physical_address += asked_page_size;
                virtual_address += asked_page_size;
            }) {
                try map_4k_page(vas_cr3, physical_address, virtual_address, flags, physical_allocator);
            }
        },
        else => @compileError("Invalid reverse valid page size"),
    }
}

fn map_1gb_page(vas_cr3: cr3, physical_address: u64, virtual_address: u64, flags: MemoryFlags, physical_allocator: *Allocator) !void {
    const indices = compute_indices(virtual_address);

    const pml4_table = get_pml4_table(vas_cr3);
    const pdp_table = get_pdp_table(pml4_table, indices, physical_allocator);

    try page_tables_map_1_gb_page(pdp_table, indices, physical_address, flags);
}

fn map_2mb_page(vas_cr3: cr3, physical_address: u64, virtual_address: u64, flags: MemoryFlags, physical_allocator: *Allocator) !void {
    const indices = compute_indices(virtual_address);

    const pml4_table = get_pml4_table(vas_cr3);
    const pdp_table = get_pdp_table(pml4_table, indices, physical_allocator);
    const pd_table = get_pd_table(pdp_table, indices, physical_allocator);

    try page_tables_map_2_mb_page(pd_table, indices, physical_address, flags);
}

fn map_4k_page(vas_cr3: cr3, physical_address: u64, virtual_address: u64, flags: MemoryFlags, physical_allocator: *Allocator) MapError!void {
    const indices = compute_indices(virtual_address);

    const pml4_table = get_pml4_table(vas_cr3);
    const pdp_table = get_pdp_table(pml4_table, indices, physical_allocator);
    const pd_table = get_pd_table(pdp_table, indices, physical_allocator);
    const p_table = get_p_table(pd_table, indices, physical_allocator);

    try page_tables_map_4_kb_page(p_table, indices, physical_address, flags);
}

pub fn getPageTableVirtualAddress(physical_address: PhysicalAddress(.local)) VirtualAddress(.local) {
    return switch (lib.cpu.arch) {
        .x86 => physical_address.toIdentityMappedVirtualAddress(),
        .x86_64 => switch (lib.os) {
            .freestanding => physical_address.toHigherHalfVirtualAddress(),
            .uefi => physical_address.toIdentityMappedVirtualAddress(),
            else => @compileError("OS not supported"),
        },
        else => @compileError("Architecture not supported"),
    };
}

fn get_pml4_table(cr3_register: cr3) *volatile PML4Table {
    const pml4_physical_address = cr3_register.getAddress();
    const pml4_virtual_address = getPageTableVirtualAddress(pml4_physical_address);
    if (lib.config.safe_slow) {
        assert(pml4_virtual_address.is_valid());
    }

    return pml4_virtual_address.access(*volatile PML4Table);
}

fn get_pdp_table(pml4_table: *volatile PML4Table, indices: Indices, physical_allocator: *Allocator) *volatile PDPTable {
    const entry_pointer = &pml4_table[indices[@enumToInt(PageIndex.PML4)]];

    const table_physical_address_value = physical_address_blk: {
        const entry_value = entry_pointer.*;
        //log.debug("PML4 entry: {}", .{entry_value});
        if (entry_value.present) {
            break :physical_address_blk unpack_address(entry_value);
        } else {
            // TODO: track this physical allocation in order to map it later in the kernel address space
            const entry_allocation = physical_allocator.allocateBytes(@sizeOf(PDPTable), valid_page_sizes[0]) catch @panic("wtf");

            entry_pointer.* = PML4TE{
                .present = true,
                .read_write = true,
                .address = pack_address(PML4TE, entry_allocation.address),
            };

            break :physical_address_blk entry_allocation.address;
        }
    };

    const table_physical_address = PhysicalAddress(.local).new(table_physical_address_value);
    const table_virtual_address = getPageTableVirtualAddress(table_physical_address);

    const is_valid = table_virtual_address.isValid();
    if (!is_valid) {
        @panic("Wtf");
        //log.debug("check pdp table valid: {}", .{is_valid});
    }

    if (lib.config.safe_slow) assert(is_valid);

    return table_virtual_address.access(*volatile PDPTable);
}

const MapError = error{
    already_present,
};

fn get_page_entry(comptime Entry: type, physical_address: u64, flags: MemoryFlags) Entry {
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

fn page_tables_map_1_gb_page(pdp_table: *volatile PDPTable, indices: Indices, physical_address: u64, flags: MemoryFlags) MapError!void {
    const entry_pointer = &pdp_table[indices[@enumToInt(PageIndex.PDP)]];

    if (entry_pointer.present) return MapError.already_present;

    assert(isAlignedGeneric(u64, physical_address, valid_page_sizes[2]));

    entry_pointer.* = @bitCast(PDPTE, get_page_entry(PDPTE_1GB, physical_address, flags));
}

fn page_tables_map_2_mb_page(pd_table: *volatile PDTable, indices: Indices, physical_address: u64, flags: MemoryFlags) !void {
    const entry_pointer = &pd_table[indices[@enumToInt(PageIndex.PD)]];
    const entry_value = entry_pointer.*;

    if (entry_value.present) return MapError.already_present;

    assert(isAlignedGeneric(u64, physical_address, valid_page_sizes[1]));

    entry_pointer.* = @bitCast(PDTE, get_page_entry(PDTE_2MB, physical_address, flags));
}

fn page_tables_map_4_kb_page(p_table: *volatile PTable, indices: Indices, physical_address: u64, flags: MemoryFlags) !void {
    const entry_pointer = &p_table[indices[@enumToInt(PageIndex.PT)]];

    if (entry_pointer.present) return MapError.already_present;

    assert(isAlignedGeneric(u64, physical_address, valid_page_sizes[0]));

    entry_pointer.* = @bitCast(PTE, get_page_entry(PTE, physical_address, flags));
    log.debug("Final Entry: {}", .{entry_pointer.*});
}

fn get_pd_table(pdp_table: *volatile PDPTable, indices: Indices, physical_allocator: *Allocator) *volatile PDTable {
    const entry_pointer = &pdp_table[indices[@enumToInt(PageIndex.PDP)]];

    const table_physical_address_value = physical_address_blk: {
        const entry_value = entry_pointer.*;
        if (entry_value.present) {
            // The address is mapped with a 1GB page
            if (entry_value.page_size) {
                @panic("todo pd table page size");
            }
            break :physical_address_blk unpack_address(entry_value);
        } else {
            // TODO: track this physical allocation in order to map it later in the kernel address space
            const entry_allocation = physical_allocator.allocateBytes(@sizeOf(PDTable), valid_page_sizes[0]) catch @panic("wtf");

            entry_pointer.* = PDPTE{
                .present = true,
                .read_write = true,
                .address = pack_address(PDPTE, entry_allocation.address),
            };

            break :physical_address_blk entry_allocation.address;
        }
    };

    const table_physical_address = PhysicalAddress(.local).new(table_physical_address_value);
    const table_virtual_address = getPageTableVirtualAddress(table_physical_address);
    if (lib.config.safe_slow) assert(table_virtual_address.is_valid());
    return table_virtual_address.access(*volatile PDTable);
}

fn get_p_table(pd_table: *volatile PDTable, indices: Indices, physical_allocator: *Allocator) *volatile PTable {
    const entry_pointer = &pd_table[indices[@enumToInt(PageIndex.PD)]];

    const table_physical_address_value = physical_address_blk: {
        const entry_value = entry_pointer.*;
        if (entry_value.present) {
            // The address is mapped with a 2MB page
            if (entry_value.page_size) {
                @panic("todo ptable page size");
            }
            break :physical_address_blk unpack_address(entry_value);
        } else {
            const entry_allocation = physical_allocator.allocateBytes(@sizeOf(PTable), valid_page_sizes[0]) catch @panic("wtf");

            entry_pointer.* = PDTE{
                .present = true,
                .read_write = true,
                .address = pack_address(PDTE, entry_allocation.address),
            };

            break :physical_address_blk entry_allocation.address;
        }
    };

    const table_physical_address = PhysicalAddress(.local).new(table_physical_address_value);
    const table_virtual_address = getPageTableVirtualAddress(table_physical_address);

    if (lib.config.safe_slow) assert(table_virtual_address.is_valid());

    return table_virtual_address.access(*volatile PTable);
}

const half_entry_count = (@sizeOf(PML4Table) / @sizeOf(PML4TE)) / 2;

pub const needed_physical_memory_for_bootstrapping_kernel_address_space = @sizeOf(PML4Table) + @sizeOf(PDPTable) * 256;

pub fn initKernelBSP(allocation_region: privileged.GenericPhysicalMemoryRegion(.x86_64, .local)) VirtualAddressSpace {
    const pml4_physical_region = allocation_region.takeSlice(@sizeOf(PML4Table));
    const pdp_physical_region = allocation_region.offset(@sizeOf(PML4Table));

    //log.debug("PML4", .{});
    const pml4_entries = switch (lib.cpu.arch) {
        .x86 => pml4_physical_region.toIdentityMappedVirtualAddress().access(PML4TE),
        .x86_64 => switch (lib.os) {
            .freestanding => pml4_physical_region.toHigherHalfVirtualAddress().access(PML4TE),
            .uefi => pml4_physical_region.toIdentityMappedVirtualAddress().access(PML4TE),
            else => @compileError("OS not supported"),
        },
        else => @compileError("Architecture panic"),
    };

    for (pml4_entries[0..half_entry_count]) |*entry| {
        entry.* = @bitCast(PML4TE, @as(u64, 0));
    }

    //log.debug("PML4 entries", .{});
    for (pml4_entries[half_entry_count..]) |*entry, i| {
        entry.* = PML4TE{
            .present = true,
            .read_write = true,
            .address = pack_address(PML4TE, pdp_physical_region.offset(i * @sizeOf(PDPTable)).address.value()),
        };
    }

    return .{
        .arch = .{
            .cr3 = cr3.from_address(pml4_physical_region.address),
        },
    };
}

pub fn make_current(virtual_address_space: *const VirtualAddressSpace) void {
    virtual_address_space.arch.cr3.write();
}

pub fn init_user(virtual_address_space: *VirtualAddressSpace, physical_address_space: *PhysicalAddressSpace) void {
    if (lib.config.safe_slow) assert(virtual_address_space.privilege_level == .user);
    const pml4_physical_region = physical_address_space.allocate(@sizeOf(PML4Table), valid_page_sizes[0]) catch @panic("Wtf");
    virtual_address_space.arch = Specific{
        .cr3 = cr3.from_address(pml4_physical_region.address),
    };

    const pml4_virtual_address = pml4_physical_region.address.toHigherHalfVirtualAddress();
    const pml4 = pml4_virtual_address.access(*PML4Table);
    const lower_half_pml4 = pml4[0 .. pml4.len / 2];
    const higher_half_pml4 = pml4[0 .. pml4.len / 2];
    for (lower_half_pml4) |*pml4e| {
        pml4e.* = zeroes(PML4TE);
    }

    if (lib.config.safe_slow) {
        assert(lower_half_pml4.len == half_entry_count);
        assert(higher_half_pml4.len == half_entry_count);
    }

    map_kernel_address_space_higher_half(virtual_address_space.arch.cr3, cr3.read());
}

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
        .arch = Specific{
            .cr3 = cr3.read(),
        },
        .privileged = true,
        .owner = owner,
    };
}

pub fn map_kernel_address_space_higher_half(new_cr3: cr3, kernel_cr3: cr3) void {
    const cr3_physical_address = new_cr3.getAddress();
    const cr3_virtual_address = cr3_physical_address.toHigherHalfVirtualAddress();
    // TODO: maybe user flag is not necessary?
    const pml4 = cr3_virtual_address.access(*PML4Table);
    for (pml4[0..0x100]) |*entry| {
        entry.* = zeroes(PML4TE);
    }
    copy(PML4TE, pml4[0x100..], kernel_cr3.getAddress().toHigherHalfVirtualAddress().access(*PML4Table)[0x100..]);
}

fn compute_indices(virtual_address: u64) Indices {
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

var paging_physical_allocator: ?*Allocator = null;

pub fn register_physical_allocator(allocator: *Allocator) void {
    paging_physical_allocator = allocator;
}

pub fn map_device(asked_physical_address: PhysicalAddress(.global), size: u64) !VirtualAddress(.global) {
    try map_function(cr3.read(), asked_physical_address.value(), asked_physical_address.toHigherHalfVirtualAddress().value(), size, .{
        .read_write = true,
        .cache_disable = true,
        .global = false,
    }, paging_physical_allocator orelse unreachable);

    return asked_physical_address.toHigherHalfVirtualAddress();
}

pub inline fn new_flags(general_flags: VirtualAddressSpace.Flags, comptime core_locality: privileged.CoreLocality) MemoryFlags {
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

fn unpack_address(entry: anytype) u64 {
    const T = @TypeOf(entry);
    const address_offset = @bitOffsetOf(T, "address");
    return @as(u64, entry.address) << address_offset;
}

fn get_address_type(comptime T: type) type {
    var a: T = undefined;
    return @TypeOf(@field(a, "address"));
}

fn pack_address(comptime T: type, physical_address: u64) get_address_type(T) {
    const address_offset = @bitOffsetOf(T, "address");
    return @intCast(get_address_type(T), physical_address >> address_offset);
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

const PML4Table = [512]PML4TE;
const PDPTable = [512]PDPTE;
const PDTable = [512]PDTE;
const PTable = [512]PTE;

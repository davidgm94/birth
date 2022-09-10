const std = @import("../../../common/std.zig");

const common = @import("common.zig");
const crash = @import("../../crash.zig");
const Bitflag = @import("../../../common/bitflag.zig").Bitflag;
const kernel = @import("../../kernel.zig");
const PhysicalAddress = @import("../../physical_address.zig");
const PhysicalAddressSpace = @import("../../physical_address_space.zig");
const registers = @import("registers.zig");
const Timer = @import("../../timer.zig");
const VirtualAddress = @import("../../virtual_address.zig");
const VirtualAddressSpace = @import("../../virtual_address_space.zig");
const VirtualMemoryRegion = @import("../../virtual_memory_region.zig");
const x86_64 = @import("common.zig");

const cr3 = registers.cr3;
const log = std.log.scoped(.VAS);
const MapError = VirtualAddressSpace.MapError;
const page_size = common.page_size;

pub const Specific = struct {
    cr3: cr3 = undefined,

    pub fn format(specific: Specific, comptime _: []const u8, _: std.InternalFormatOptions, writer: anytype) @TypeOf(writer).Error!void {
        try std.internal_format(writer, "{}", .{specific.cr3});
    }
};

const Indices = [std.enum_count(PageIndex)]u16;

pub var bootstrapping_physical_addresses: std.ArrayList(PhysicalAddress) = undefined;

pub fn map(virtual_address_space: *VirtualAddressSpace, physical_address: PhysicalAddress, virtual_address: VirtualAddress, flags: MemoryFlags, comptime is_bootstraping: bool, higher_half_direct_map: u64) MapError!void {
    var allocation_count: u64 = 0;

    if (safe_map) {
        @panic("TODO safe map map");
        //std.assert((PhysicalAddress{ .value = virtual_address_space.arch.cr3 }).is_valid());
        //std.assert(std.is_aligned(virtual_address.value, common.page_size));
        //std.assert(std.is_aligned(physical_address.value, common.page_size));
    }

    const indices = compute_indices(virtual_address);

    const is_bootstrapping_address_space = virtual_address_space == kernel.bootstrap_virtual_address_space;

    var pdp: *volatile PDPTable = undefined;
    {
        const pml4_physical_address = get_pml4_physical_address(virtual_address_space);
        var pml4_virtual_address = VirtualAddress.invalid();
        const page_count = @divExact(@sizeOf(PML4Table), page_size);
        _ = page_count;

        if (is_bootstraping) {
            if (is_bootstrapping_address_space) {
                @panic("bootstrapping address space");
            } else {
                std.assert(virtual_address_space == &kernel.virtual_address_space);
                // In this situation, when we rely on the bootloader address space, it's assumed that the PML4 physical address is identity mapped
                // Check for this fn new in this same module
                pml4_virtual_address = pml4_physical_address.to_identity_mapped_virtual_address();
            }
        } else {
            std.assert(!is_bootstrapping_address_space);
            std.assert(virtual_address_space != kernel.bootstrap_virtual_address_space);
            @panic("ni");
        }
        std.assert(pml4_virtual_address.is_valid());

        var pml4 = pml4_virtual_address.access(*PML4Table);
        var pml4_entry = &pml4[indices[@enumToInt(PageIndex.PML4)]];
        var pml4_entry_value = pml4_entry.value;

        if (pml4_entry_value.contains(.present)) {
            const entry_physical_address = get_address_from_entry_bits(pml4_entry_value.bits);
            const entry_virtual_address = if (is_bootstraping) entry_physical_address.to_virtual_address_with_offset(higher_half_direct_map) else entry_physical_address.to_higher_half_virtual_address();
            pdp = entry_virtual_address.access(*volatile PDPTable);
        } else {
            log.debug("PML4 entry value: 0x{x}", .{pml4_entry_value.bits});
            @panic("pml4 not implemented");
        }
    }

    if (true) @panic("next step");

    var pd: *volatile PDTable = undefined;
    {
        var pdp_entry = &pdp[indices[@enumToInt(PageIndex.PDP)]];
        var pdp_entry_value = pdp_entry.value;

        if (pdp_entry_value.contains(.present)) {
            const entry_physical_address = get_address_from_entry_bits(pdp_entry_value.bits);
            const entry_virtual_address = if (is_bootstraping and is_bootstrapping_address_space) entry_physical_address.to_virtual_address_with_offset(0) else if (is_bootstraping) entry_physical_address.to_virtual_address_with_offset(higher_half_direct_map) else entry_physical_address.to_higher_half_virtual_address();
            pd = entry_virtual_address.access(@TypeOf(pd));
        } else {
            defer allocation_count += 1;

            const page_count = @divExact(@sizeOf(PDTable), common.page_size);
            const entry_physical_address = kernel.physical_address_space.allocate(page_count) orelse @panic("unable to alloc pd");
            // This address does not need to be mapped since it will be mapped later on when the used physical address space bitset memory
            const entry_virtual_address = if (is_bootstraping and is_bootstrapping_address_space) entry_physical_address.to_virtual_address_with_offset(0) else if (is_bootstraping) entry_physical_address.to_virtual_address_with_offset(higher_half_direct_map) else entry_physical_address.to_higher_half_virtual_address();
            //log.debug("Allocating PD: (0x{x}, 0x{x}). Bootstrapping: {}", .{ entry_physical_address.value, entry_virtual_address.value, is_bootstraping });

            if (is_bootstraping and !is_bootstrapping_address_space) {
                var mapped = false;
                if (get_mapped_address_bootstrapping(entry_virtual_address, entry_physical_address, .not_panic)) |mapped_address| {
                    if (mapped_address.value == entry_physical_address.value) mapped = true else @panic("WTF");
                }

                if (!mapped) {
                    if (kernel.bootstrap_virtual_address_space.lock.status != 0) {
                        kernel.bootstrap_virtual_address_space.map_extended(entry_physical_address, entry_virtual_address, page_count, .{ .write = true }, VirtualAddressSpace.AlreadyLocked.yes, is_bootstraping, higher_half_direct_map) catch unreachable;
                    } else {
                        kernel.bootstrap_virtual_address_space.map_extended(entry_physical_address, entry_virtual_address, page_count, .{ .write = true }, VirtualAddressSpace.AlreadyLocked.no, is_bootstraping, higher_half_direct_map) catch unreachable;
                    }
                }

                _ = get_mapped_address_bootstrapping(entry_virtual_address, entry_physical_address, .panic);
                //log.debug("#{} Adding 0x{x}", .{ bootstrapping_physical_addresses.items.len, entry_physical_address.value });
                bootstrapping_physical_addresses.append(kernel.bootstrap_allocator.allocator(), entry_physical_address) catch unreachable;
            } else {
                @panic("todo");
            }

            pd = entry_virtual_address.access(@TypeOf(pd));
            pd.* = std.zeroes(PDTable);
            pdp_entry_value.or_flag(.present);
            pdp_entry_value.or_flag(.read_write);
            pdp_entry_value.or_flag(.user);
            pdp_entry_value.bits = set_entry_in_address_bits(pdp_entry_value.bits, entry_physical_address);
            pdp_entry.value = pdp_entry_value;
        }
    }

    var pt: *volatile PTable = undefined;
    {
        var pd_entry = &pd[indices[@enumToInt(PageIndex.PD)]];
        var pd_entry_value = pd_entry.value;

        if (pd_entry_value.contains(.present)) {
            const entry_physical_address = get_address_from_entry_bits(pd_entry_value.bits);
            const entry_virtual_address = if (is_bootstraping and is_bootstrapping_address_space) entry_physical_address.to_virtual_address_with_offset(0) else if (is_bootstraping) entry_physical_address.to_virtual_address_with_offset(higher_half_direct_map) else entry_physical_address.to_higher_half_virtual_address();
            pt = entry_virtual_address.access(@TypeOf(pt));
        } else {
            defer allocation_count += 1;

            const page_count = @divExact(@sizeOf(PDTable), common.page_size);
            const entry_physical_address = kernel.physical_address_space.allocate(page_count) orelse @panic("unable to alloc pt");
            const entry_virtual_address = if (is_bootstraping and is_bootstrapping_address_space) entry_physical_address.to_virtual_address_with_offset(0) else if (is_bootstraping) entry_physical_address.to_virtual_address_with_offset(higher_half_direct_map) else entry_physical_address.to_higher_half_virtual_address();
            //log.debug("Allocating PT: (0x{x}, 0x{x})", .{ entry_physical_address.value, entry_virtual_address.value });

            if (is_bootstraping and !is_bootstrapping_address_space) {
                var mapped = false;
                if (get_mapped_address_bootstrapping(entry_virtual_address, entry_physical_address, .not_panic)) |mapped_address| {
                    if (mapped_address.value == entry_physical_address.value) mapped = true else @panic("WTF");
                }

                if (!mapped) {
                    if (kernel.bootstrap_virtual_address_space.lock.status != 0) {
                        kernel.bootstrap_virtual_address_space.map_extended(entry_physical_address, entry_virtual_address, page_count, .{ .write = true }, VirtualAddressSpace.AlreadyLocked.yes, is_bootstraping, higher_half_direct_map) catch unreachable;
                    } else {
                        kernel.bootstrap_virtual_address_space.map_extended(entry_physical_address, entry_virtual_address, page_count, .{ .write = true }, VirtualAddressSpace.AlreadyLocked.no, is_bootstraping, higher_half_direct_map) catch unreachable;
                    }
                }

                _ = get_mapped_address_bootstrapping(entry_virtual_address, entry_physical_address, .panic);
                //log.debug("#{} Adding 0x{x}", .{ bootstrapping_physical_addresses.items.len, entry_physical_address.value });
                bootstrapping_physical_addresses.append(kernel.bootstrap_allocator.allocator(), entry_physical_address) catch unreachable;
            } else {
                @panic("todo");
            }

            pt = entry_virtual_address.access(@TypeOf(pt));
            pt.* = std.zeroes(PTable);
            pd_entry_value.or_flag(.present);
            pd_entry_value.or_flag(.read_write);
            pd_entry_value.or_flag(.user);
            pd_entry_value.bits = set_entry_in_address_bits(pd_entry_value.bits, entry_physical_address);
            pd_entry.value = pd_entry_value;
        }
    }

    const pte_ptr = &pt[indices[@enumToInt(PageIndex.PT)]];
    if (pte_ptr.value.contains(.present)) {
        const already_mapped_physical_address = pte_ptr.value.bits & address_mask;
        log.err("Page 0x{x} was already mapped to 0x{x}", .{ virtual_address.value, already_mapped_physical_address });
        return MapError.already_present;
    }

    pte_ptr.* = blk: {
        var pte = PTE{
            .value = PTE.Flags.from_bits(flags.bits),
        };

        pte.value.or_flag(.present);
        pte.value.bits = set_entry_in_address_bits(pte.value.bits, physical_address);

        break :blk pte;
    };
}

pub fn new(virtual_address_space: *VirtualAddressSpace, physical_address_space: *PhysicalAddressSpace, higher_half_direct_map: u64) void {
    const is_kernel_address_space = virtual_address_space == &kernel.virtual_address_space;
    std.assert((virtual_address_space.privilege_level == .kernel) == is_kernel_address_space);
    _ = higher_half_direct_map;

    if (is_kernel_address_space) {
        const half_entry_count = 0x100;
        const pml4_table_page_count = comptime @divExact(@sizeOf(PML4Table), common.page_size);
        const pdp_table_page_count = comptime @divExact(@sizeOf(PDPTable), common.page_size);
        const page_count = pml4_table_page_count + (pdp_table_page_count * half_entry_count);
        const allocation_chunk_physical_address = physical_address_space.allocate(page_count) orelse @panic("wtf");

        if (safe_map) {
            var physical_address = allocation_chunk_physical_address;
            const top_physical_address = physical_address.offset(page_count * page_size);

            // Sanity check to ensure all addresses are identity mapped in the bootstrapping address space
            while (physical_address.value < top_physical_address.value) : (physical_address.value += page_size) {
                _ = get_mapped_address_bootstrapping(physical_address.to_identity_mapped_virtual_address(), physical_address, .panic);
            }
        }

        @panic("TODO VAS new");

        //virtual_address_space.arch = Specific{
        //.cr3 = allocation_chunk_physical_address,
        //};

        //const cr3_virtual_address = virtual_address_space.arch.to_identity_mapped_virtual_address();
        //const pml4 = cr3_virtual_address.access(*PML4Table);
        //const lower_half_pml4 = pml4[0 .. pml4.len / 2];
        //const higher_half_pml4 = pml4[0 .. pml4.len / 2];
        //std.assert(lower_half_pml4.len == 0x100);
        //std.assert(higher_half_pml4.len == 0x100);
        //std.zero_slice(PML4E, lower_half_pml4);
        //_ = higher_half_pml4;
    } else {
        @panic("TODO: implement user address spaces");
    }
}

const safe_map = true;
const time_map = false;

const PanicPolicy = enum {
    panic,
    not_panic,
};

fn get_mapped_address_bootstrapping(virtual_address: VirtualAddress, physical_address: PhysicalAddress, comptime panic_policy: PanicPolicy) ?PhysicalAddress {
    std.assert(kernel.bootstrap_virtual_address_space.valid);
    //log.debug("[Boostrapping] Checking if VA 0x{x} is mapped to PA: 0x{x}. Panicking if not", .{ virtual_address.value, physical_address.value });
    if (kernel.bootstrap_virtual_address_space.translate_address_extended(virtual_address, if (kernel.bootstrap_virtual_address_space.lock.status != 0) .yes else .no, true)) |mapped_address| {
        if (mapped_address.value != physical_address.value) {
            log.err("VA 0x{x} is already mapped to PA 0x{x}", .{ virtual_address.value, physical_address.value });
            if (panic_policy == .panic) @panic("WTF");
        } else {
            return mapped_address;
        }
    } else {
        log.err("VA 0x{x} is not mapped to any address", .{virtual_address.value});
        std.assert(!kernel.higher_half_direct_map.is_valid());
        const hardcoded_value = 0xffff800000000000;
        if (panic_policy == .panic) {
            if (kernel.bootstrap_virtual_address_space.translate_address_extended(virtual_address.offset(hardcoded_value), if (kernel.bootstrap_virtual_address_space.lock.status != 0) .yes else .no, true)) |mapped_address| {
                _ = mapped_address;
                @panic("mapped");
            } else {
                @panic("not mapped");
            }
        }
        if (panic_policy == .panic) @panic("WTF");
    }

    return null;
}

pub inline fn switch_address_spaces_if_necessary(new_address_space: *VirtualAddressSpace) void {
    _ = new_address_space;
    @panic("TODO: switch address spaces if necessary");
    //const current_cr3 = cr3.read_raw();
    //if (current_cr3 != new_address_space.arch.cr3) {
    //cr3.write_raw(new_address_space.arch.cr3);
    //}
}

pub inline fn is_current(virtual_address_space: *VirtualAddressSpace) bool {
    _ = virtual_address_space;
    return false;
    //const current = cr3.read_raw();
    //return current == virtual_address_space.arch.cr3;
}

pub inline fn from_current(virtual_address_space: *VirtualAddressSpace) void {
    virtual_address_space.* = VirtualAddressSpace{
        .arch = Specific{
            .cr3 = cr3.read(),
        },
        .privilege_level = .kernel,
        .heap = .{},
        .lock = .{},
        .valid = true,
    };
}

pub fn get_pml4_physical_address(virtual_address_space: *VirtualAddressSpace) PhysicalAddress {
    return virtual_address_space.arch.cr3.get_address();
}

pub fn map_kernel_address_space_higher_half(virtual_address_space: *VirtualAddressSpace, kernel_address_space: *VirtualAddressSpace) void {
    _ = virtual_address_space;
    _ = kernel_address_space;
    @panic("TODO: map kernel address space higher_half");
    //const cr3_physical_address = PhysicalAddress.new(virtual_address_space.arch.cr3);
    //const cr3_kernel_virtual_address = cr3_physical_address.to_higher_half_virtual_address();
    //// TODO: maybe user flag is not necessary?
    //kernel_address_space.map(cr3_physical_address, cr3_kernel_virtual_address, 1, .{ .write = true, .user = true }) catch unreachable;
    //const pml4 = cr3_kernel_virtual_address.access(*PML4Table);
    //std.zero_slice(PML4E, pml4[0..0x100]);
    //if (true) @panic("fix this map kernel address space higher half");
    ////std.copy(PML4E, pml4[0x100..], PhysicalAddress.new(kernel_address_space.arch.cr3).access_higher_half(*PML4Table)[0x100..]);
    //log.debug("USER CR3: 0x{x}", .{cr3_physical_address.value});
}

pub fn translate_address(virtual_address_space: *VirtualAddressSpace, asked_virtual_address: VirtualAddress, comptime is_bootstraping: bool) ?PhysicalAddress {
    std.assert(asked_virtual_address.is_valid());
    const virtual_address = asked_virtual_address.aligned_backward(common.page_size);
    const indices = compute_indices(virtual_address);

    const is_bootstrapping_address_space = is_bootstraping and virtual_address_space == kernel.bootstrap_virtual_address_space;
    const virtual_address_offset: u64 = if (is_bootstrapping_address_space) 0 else kernel.higher_half_direct_map.value;
    std.assert((kernel.higher_half_direct_map.value == 0) == is_bootstraping);

    var pdp: *volatile PDPTable = undefined;
    {
        var pml4 = get_pml4_physical_address(virtual_address_space).to_virtual_address_with_offset(virtual_address_offset).access(*PML4Table);
        const pml4_entry = &pml4[indices[@enumToInt(PageIndex.PML4)]];
        var pml4_entry_value = pml4_entry.value;

        if (!pml4_entry_value.contains(.present)) {
            log.err("PML4 entry present for {} when translating virtual address {}", .{ virtual_address_space, asked_virtual_address });
            return null;
        }

        pdp = get_address_from_entry_bits(pml4_entry_value.bits).to_virtual_address_with_offset(virtual_address_offset).access(@TypeOf(pdp));
    }

    var pd: *volatile PDTable = undefined;
    {
        var pdp_entry = &pdp[indices[@enumToInt(PageIndex.PDP)]];
        var pdp_entry_value = pdp_entry.value;

        if (!pdp_entry_value.contains(.present)) {
            log.err("PDP entry present for {} when translating virtual address {}", .{ virtual_address_space, asked_virtual_address });
            return null;
        }

        pd = get_address_from_entry_bits(pdp_entry_value.bits).to_virtual_address_with_offset(virtual_address_offset).access(@TypeOf(pd));
    }

    var pt: *volatile PTable = undefined;
    {
        var pd_entry = &pd[indices[@enumToInt(PageIndex.PD)]];
        var pd_entry_value = pd_entry.value;

        if (!pd_entry_value.contains(.present)) {
            log.err("PDP entry present for {} when translating virtual address {}", .{ virtual_address_space, asked_virtual_address });
            return null;
        }

        pt = get_address_from_entry_bits(pd_entry_value.bits).to_virtual_address_with_offset(virtual_address_offset).access(@TypeOf(pt));
    }

    const pte = pt[indices[@enumToInt(PageIndex.PT)]];
    if (!pte.value.contains(.present)) return null;

    const base_physical_address = get_address_from_entry_bits(pte.value.bits);
    const offset = asked_virtual_address.value - virtual_address.value;
    if (offset != 0) @panic("Error translating address: offset not zero");

    return PhysicalAddress.new(base_physical_address.value + offset);
}

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
    _ = virtual_address_space;
    @panic("TODO make current");
    //cr3.write_raw(virtual_address_space.arch.cr3);
}

pub inline fn new_flags(general_flags: VirtualAddressSpace.Flags) MemoryFlags {
    var flags = MemoryFlags.empty();
    if (general_flags.write) flags.or_flag(.read_write);
    if (general_flags.user) flags.or_flag(.user);
    if (general_flags.cache_disable) flags.or_flag(.cache_disable);
    if (general_flags.accessed) flags.or_flag(.accessed);
    if (!general_flags.execute) flags.or_flag(.execute_disable);
    return flags;
}

// TODO:
pub const MemoryFlags = Bitflag(true, u64, enum(u6) {
    read_write = 1,
    user = 2,
    write_through = 3,
    cache_disable = 4,
    accessed = 5,
    dirty = 6,
    pat = 7, // must be 0
    global = 8,
    execute_disable = 63,
});

const address_mask: u64 = 0x0000_00ff_ffff_f000;

fn set_entry_in_address_bits(old_entry_value: u64, new_address: PhysicalAddress) u64 {
    if (safe_map) {
        std.assert(x86_64.max_physical_address_bit == 40);
        std.assert(std.is_aligned(new_address.value, common.page_size));
    }

    const address_masked = new_address.value & address_mask;
    const old_entry_value_masked = old_entry_value & ~address_masked;
    const result = address_masked | old_entry_value_masked;

    return result;
}

inline fn get_address_from_entry_bits(entry_bits: u64) PhysicalAddress {
    const address = entry_bits & address_mask;
    if (safe_map) {
        std.assert(common.max_physical_address_bit == 40);
        std.assert(std.is_aligned(address, common.page_size));
    }

    return PhysicalAddress.new(address);
}

const PageIndex = enum(u3) {
    PML4 = 0,
    PDP = 1,
    PD = 2,
    PT = 3,
};

const PML4E = struct {
    value: Flags,

    const Flags = Bitflag(true, u64, enum(u6) {
        present = 0,
        read_write = 1,
        user = 2,
        page_level_write_through = 3,
        page_level_cache_disable = 4,
        accessed = 5,
        hlat_restart = 11,
        execute_disable = 63, // IA32_EFER.NXE must be 1
    });
};

const PDPTE = struct {
    value: Flags,

    const Flags = Bitflag(true, u64, enum(u6) {
        present = 0,
        read_write = 1,
        user = 2,
        page_level_write_through = 3,
        page_level_cache_disable = 4,
        accessed = 5,
        page_size = 7, // must be 0
        hlat_restart = 11,
        execute_disable = 63, // IA32_EFER.NXE must be 1
    });
};

const PDE = struct {
    value: Flags,

    const Flags = Bitflag(true, u64, enum(u6) {
        present = 0,
        read_write = 1,
        user = 2,
        page_level_write_through = 3,
        page_level_cache_disable = 4,
        accessed = 5,
        page_size = 7, // must be 0
        hlat_restart = 11,
        execute_disable = 63, // IA32_EFER.NXE must be 1
    });
};

const PTE = struct {
    value: Flags,

    const Flags = Bitflag(true, u64, enum(u6) {
        present = 0,
        read_write = 1,
        user = 2,
        page_level_write_through = 3,
        page_level_cache_disable = 4,
        accessed = 5,
        dirty = 6,
        pat = 7, // must be 0
        global = 8,
        hlat_restart = 11,
        // TODO: protection key
        execute_disable = 63, // IA32_EFER.NXE must be 1
    });
};

const PML4Table = [512]PML4E;
const PDPTable = [512]PDPTE;
const PDTable = [512]PDE;
const PTable = [512]PTE;

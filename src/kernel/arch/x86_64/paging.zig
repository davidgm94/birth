// Paging behavior is controlled by the following control bits:
// • The WP and PG flags in control register CR0 (bit 16 and bit 31, respectively).
// • The PSE, PAE, PGE, LA57, PCIDE, SMEP, SMAP, PKE, CET, and PKS flags in control register CR4 (bit 4, bit 5, bit 7, bit 12, bit 17, bit 20, bit 21, bit 22, bit 23, and bit 24, respectively).
// • The LME and NXE flags in the IA32_EFER MSR (bit 8 and bit 11, respectively).
// • The AC flag in the EFLAGS register (bit 18).
// • The “enable HLAT” VM-execution control (tertiary processor-based VM-execution control bit 1; see Section 24.6.2, “Processor-Based VM-Execution Controls,” in the Intel® 64 and IA-32 Architectures Software Developer’s Manual, Volume 3C).

const kernel = @import("../../kernel.zig");
const x86_64 = @import("../x86_64.zig");

const Physical = kernel.Physical;
const Virtual = kernel.Virtual;
const TODO = kernel.TODO;
const log = kernel.log.scoped(.Paging_x86_64);

const PML4Table = [512]PML4E;
const PDPTable = [512]PDPTE;
const PDTable = [512]PDE;
const PTable = [512]PTE;

pub fn init() void {
    const pml4e = kernel.PhysicalMemory.allocate_pages(kernel.bytes_to_pages(@sizeOf(PML4Table), true)) orelse @panic("unable to allocate memory for PML4E");
    kernel.zero(pml4e.access_identity([*]u8)[0..@sizeOf(PML4Table)]);

    var address_space = kernel.Virtual.AddressSpace.new(pml4e.value);

    // Map the kernel and do some tests
    {
        var current_address_space = kernel.Virtual.AddressSpace.new(x86_64.cr3.read_raw());
        kernel.assert(@src(), kernel.sections_in_memory.len > 0);
        for (kernel.sections_in_memory) |section| {
            const section_physical_address = current_address_space.translate_address(section.descriptor.address) orelse @panic("address not translated");
            section.descriptor.map(&address_space, section_physical_address);
        }
    }

    for (kernel.PhysicalMemory.map.usable) |region| {
        // Identity map it
        region.descriptor.map(&address_space, region.descriptor.address.identity_virtual_address());
    }
    log.debug("Mapped usable", .{});

    for (kernel.PhysicalMemory.map.reclaimable) |region| {
        // Identity map it
        region.descriptor.map(&address_space, region.descriptor.address.identity_virtual_address());
    }
    log.debug("Mapped reclaimable", .{});

    for (kernel.PhysicalMemory.map.framebuffer) |region| {
        // Identity map it
        region.map(&address_space, region.address.identity_virtual_address());
    }
    log.debug("Mapped framebuffer", .{});

    x86_64.cr3.write_raw(address_space.arch.cr3);
    log.debug("Memory mapping initialized!", .{});
}

pub const AddressSpace = struct {
    cr3: u64,

    const Indices = [kernel.enum_values(PageIndex).len]u16;

    pub inline fn new(context: anytype) AddressSpace {
        comptime kernel.assert_unsafe(@TypeOf(context) == u64);
        const cr3 = context;
        return AddressSpace{
            .cr3 = cr3,
        };
    }

    pub fn map(arch_address_space: *AddressSpace, physical_address: Physical.Address, virtual_address: Virtual.Address) void {
        kernel.assert(@src(), physical_address.is_page_aligned());
        kernel.assert(@src(), virtual_address.is_page_aligned());

        const indices = compute_indices(virtual_address.value);

        var pdp: *volatile [512]PDPTE = undefined;
        {
            const pml4 = @intToPtr(*volatile [512]PML4E, arch_address_space.cr3);
            const pml4_entry = &pml4[indices[@enumToInt(PageIndex.PML4)]];
            var pml4_entry_value = pml4_entry.value;

            if (pml4_entry_value.contains(.present)) {
                pdp = @intToPtr(@TypeOf(pdp), get_address_from_entry_bits(pml4_entry_value.bits).value);
            } else {
                const pdp_allocation = kernel.PhysicalMemory.allocate_pages(kernel.bytes_to_pages(@sizeOf([512]PDPTE), true)) orelse @panic("unable to alloc pdp");
                pdp = pdp_allocation.access_identity(@TypeOf(pdp));
                pdp.* = kernel.zeroes([512]PDPTE);
                pml4_entry_value.or_flag(.present);
                pml4_entry_value.or_flag(.read_write);
                pml4_entry_value.bits = set_entry_in_address_bits(pml4_entry_value.bits, pdp_allocation);
                pml4_entry.value = pml4_entry_value;
            }
        }

        var pd: *volatile [512]PDE = undefined;
        {
            var pdp_entry = &pdp[indices[@enumToInt(PageIndex.PDP)]];
            var pdp_entry_value = pdp_entry.value;

            if (pdp_entry_value.contains(.present)) {
                pd = get_address_from_entry_bits(pdp_entry_value.bits).access_identity(@TypeOf(pd));
            } else {
                const pd_allocation = kernel.PhysicalMemory.allocate_pages(kernel.bytes_to_pages(@sizeOf([512]PDE), true)) orelse @panic("unable to alloc pd");
                pd = pd_allocation.access_identity(@TypeOf(pd));
                pd.* = kernel.zeroes([512]PDE);
                pdp_entry_value.or_flag(.present);
                pdp_entry_value.or_flag(.read_write);
                pdp_entry_value.bits = set_entry_in_address_bits(pdp_entry_value.bits, pd_allocation);
                pdp_entry.value = pdp_entry_value;
            }
        }

        var pt: *volatile [512]PTE = undefined;
        {
            var pd_entry = &pd[indices[@enumToInt(PageIndex.PD)]];
            var pd_entry_value = pd_entry.value;

            if (pd_entry_value.contains(.present)) {
                pt = get_address_from_entry_bits(pd_entry_value.bits).access_identity(@TypeOf(pt));
            } else {
                const pt_allocation = kernel.PhysicalMemory.allocate_pages(kernel.bytes_to_pages(@sizeOf([512]PTE), true)) orelse @panic("unable to alloc pt");
                pt = pt_allocation.access_identity(@TypeOf(pt));
                pt.* = kernel.zeroes([512]PTE);
                pd_entry_value.or_flag(.present);
                pd_entry_value.or_flag(.read_write);
                pd_entry_value.bits = set_entry_in_address_bits(pd_entry_value.bits, pt_allocation);
                pd_entry.value = pd_entry_value;
            }
        }

        pt[indices[@enumToInt(PageIndex.PT)]] = blk: {
            var pte = PTE{
                .value = PTE.Flags.empty(),
            };

            pte.value.or_flag(.present);
            pte.value.or_flag(.read_write);
            pte.value.bits = set_entry_in_address_bits(pte.value.bits, physical_address);

            break :blk pte;
        };
    }

    pub fn translate_address(address_space: *AddressSpace, virtual_address: Virtual.Address) ?Physical.Address {
        kernel.assert(@src(), virtual_address.is_page_aligned());

        const indices = compute_indices(virtual_address.value);

        var pdp: *volatile [512]PDPTE = undefined;
        {
            //log.debug("CR3: 0x{x}", .{address_space.cr3});
            const pml4 = @intToPtr(*volatile [512]PML4E, address_space.cr3);
            const pml4_entry = &pml4[indices[@enumToInt(PageIndex.PML4)]];
            var pml4_entry_value = pml4_entry.value;

            if (!pml4_entry_value.contains(.present)) return null;
            //log.debug("PML4 present", .{});

            pdp = @intToPtr(@TypeOf(pdp), get_address_from_entry_bits(pml4_entry_value.bits).value);
        }

        var pd: *volatile [512]PDE = undefined;
        {
            var pdp_entry = &pdp[indices[@enumToInt(PageIndex.PDP)]];
            var pdp_entry_value = pdp_entry.value;

            if (!pdp_entry_value.contains(.present)) return null;
            //log.debug("PDP present", .{});

            pd = @intToPtr(@TypeOf(pd), get_address_from_entry_bits(pdp_entry_value.bits).value);
        }

        var pt: *volatile [512]PTE = undefined;
        {
            var pd_entry = &pd[indices[@enumToInt(PageIndex.PD)]];
            var pd_entry_value = pd_entry.value;

            if (!pd_entry_value.contains(.present)) return null;
            //log.debug("PD present", .{});

            pt = @intToPtr(@TypeOf(pt), get_address_from_entry_bits(pd_entry_value.bits).value);
        }

        const pte = pt[indices[@enumToInt(PageIndex.PT)]];
        if (!pte.value.contains(.present)) return null;
        //log.debug("PT present", .{});

        return get_address_from_entry_bits(pte.value.bits);
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

    pub fn make_current(address_space: *AddressSpace) void {
        x86_64.cr3.write_raw(address_space.cr3);
    }
};

const address_mask: u64 = 0x000000fffffff000;
fn set_entry_in_address_bits(old_entry_value: u64, new_address: Physical.Address) u64 {
    kernel.assert(@src(), kernel.Physical.Address.max_bit == 40);
    kernel.assert(@src(), new_address.is_page_aligned());
    const address_masked = new_address.value & address_mask;
    const old_entry_value_masked = old_entry_value & ~address_masked;
    const result = address_masked | old_entry_value_masked;
    return result;
}

fn get_address_from_entry_bits(entry_bits: u64) Physical.Address {
    kernel.assert(@src(), kernel.Physical.Address.max_bit == 40);
    const address = entry_bits & address_mask;
    kernel.assert(@src(), kernel.is_aligned(address, kernel.arch.page_size));

    return Physical.Address.new(address);
}

const PageIndex = enum(u3) {
    PML4 = 0,
    PDP = 1,
    PD = 2,
    PT = 3,
};

const PML4E = struct {
    value: Flags,

    const Flags = kernel.Bitflag(true, enum(u64) {
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

    const Flags = kernel.Bitflag(true, enum(u64) {
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

    const Flags = kernel.Bitflag(true, enum(u64) {
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

    const Flags = kernel.Bitflag(true, enum(u64) {
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

//const Paging = struct {
//pat: PAT,
//cr3: u64,
//level_5_paging: bool,

//write_back_virtual_base: u64 = 0,
//write_cache_virtual_base: u64 = 0,
//uncacheable_virtual_base: u64 = 0,
//max_physical_address: u64 = 0,

//pub fn init(self: *@This()) void {
//kernel.log("Initializing paging...\n");
//defer kernel.log("Paging initialized\n");
//CR0.write(CR0.read() | (1 << @enumToInt(CR0.Bit.WP)));
//CR4.write(CR4.read() | (1 << @enumToInt(CR4.Bit.PCIDE)) | (1 << @enumToInt(CR4.Bit.SMEP)));
//EFER.write(EFER.read() | (1 << @enumToInt(EFER.Bit.NXE)) | (1 << @enumToInt(EFER.Bit.SCE)) | (1 << @enumToInt(EFER.Bit.TCE)));
//const pae = CR4.get_flag(.PAE);
//kernel.assert(pae, @src());
//max_physical_address = CPUID.get_max_physical_address();
//kernel.logf("Max physical addresss: {}\n", .{max_physical_address});
//self.pat = PAT.init();
//kernel.logf("{}\n", .{self.pat});
//self.cr3 = CR3.read();
//self.level_5_paging = false;

//if (!self.level_5_paging) {
//const base = 0xFFFF800000000000;
//self.write_back_virtual_base = base;
//self.write_cache_virtual_base = base;
//self.uncacheable_virtual_base = base;
//self.max_physical_address = 0x7F0000000000;
//} else {
//TODO();
//}

//{
//kernel.log("Consuming bootloader memory map...\n");
//defer kernel.log("Memory map consumed!\n");
//for (kernel.bootloader.info.memory_map_entries[0..kernel.bootloader.info.memory_map_entry_count]) |*entry| {
//var region_address = entry.address;
//var region_size = entry.size;

//outer: while (region_size != 0) {
//for (kernel.PhysicalAllocator.reverse_sizes) |pmm_size, reverse_i| {
//const i = kernel.PhysicalAllocator.sizes.len - reverse_i - 1;
//if (region_size >= pmm_size and kernel.is_aligned(region_address, pmm_size)) {
//kernel.PhysicalAllocator.free(region_address, i);
//region_size -= pmm_size;
//region_address += pmm_size;
//continue :outer;
//}
//}

//@panic("unreachable");
//}
//}
//}

//const last_entry = kernel.bootloader.info.memory_map_entries[kernel.bootloader.info.memory_map_entry_count - 1];
//const physical_high = kernel.align_forward(last_entry.address + last_entry.size, page_size);
//_ = physical_high;

//TODO();
//}

//pub fn make_page_table() !u64 {
//const page_table = try kernel.PhysicalAllocator.allocate_physical(page_size);
//std.mem.set(u8, @intToPtr([*]u8, page_table.get_writeback_virtual_address())[0..page_size], 0);
//return page_table;
//}

//const LevelType = u3;
//const PTE = struct {
//physical_address: PhysicalAddress,
//current_level: LevelType,
//context: *Paging,
//};
//};

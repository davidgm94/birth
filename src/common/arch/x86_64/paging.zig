// Paging behavior is controlled by the following control bits:
// • The WP and PG flags in control register CR0 (bit 16 and bit 31, respectively).
// • The PSE, PAE, PGE, LA57, PCIDE, SMEP, SMAP, PKE, CET, and PKS flags in control register CR4 (bit 4, bit 5, bit 7, bit 12, bit 17, bit 20, bit 21, bit 22, bit 23, and bit 24, respectively).
// • The LME and NXE flags in the IA32_EFER MSR (bit 8 and bit 11, respectively).
// • The AC flag in the EFLAGS register (bit 18).
// • The “enable HLAT” VM-execution control (tertiary processor-based VM-execution control bit 1; see Section 24.6.2, “Processor-Based VM-Execution Controls,” in the Intel® 64 and IA-32 Architectures Software Developer’s Manual, Volume 3C).

const common = @import("../../../common.zig");

const x86_64 = common.arch.x86_64;

const TODO = common.TODO;
const log = common.log.scoped(.Paging_x86_64);
const Allocator = common.Allocator;
const VirtualAddress = common.VirtualAddress;
const VirtualMemoryRegion = common.VirtualMemoryRegion;
const PhysicalAddress = common.PhysicalAddress;
const PhysicalAddressSpace = common.PhysicalAddressSpace;

const PML4Table = [512]PML4E;
const PDPTable = [512]PDPTE;
const PDTable = [512]PDE;
const PTable = [512]PTE;

pub var should_log = false;

pub fn init(allocator: Allocator, physical_address_space: *PhysicalAddressSpace, stivale_pmrs: []x86_64.Stivale2.Struct.PMRs.PMR, cpu_features: x86_64.CPUFeatures, higher_half_direct_map: VirtualAddress) *common.VirtualAddressSpace {
    log.debug("About to dereference memory regions", .{});
    var virtual_address_space = common.VirtualAddressSpace.new(allocator, physical_address_space, cpu_features) orelse @panic("Unable to create kernel address space");

    // Map the kernel and do some tests
    {
        var bootloader_address_space = common.VirtualAddressSpace.bootstrapping(physical_address_space, cpu_features) orelse @panic("Unable to get bootstrapping address space");
        // TODO: better flags
        for (stivale_pmrs) |pmr| {
            const section_virtual_address = VirtualAddress.new(pmr.address);
            const kernel_section_virtual_region = VirtualMemoryRegion.new(section_virtual_address, pmr.size);
            const section_physical_address = bootloader_address_space.translate_address(section_virtual_address) orelse @panic("address not translated");
            virtual_address_space.map_virtual_region(kernel_section_virtual_region, section_physical_address, .{
                .execute = pmr.permissions & x86_64.Stivale2.Struct.PMRs.PMR.executable != 0,
                .write = true, //const writable = permissions & x86_64.Stivale2.Struct.PMRs.PMR.writable != 0;
            }, physical_address_space.page_size);
        }
    }

    // TODO: better flags
    for (physical_address_space.usable) |region| {
        // This needs an specific offset since the kernel value "higher_half_direct_map" is not set yet. The to_higher_half_virtual_address() function depends on this value being set.
        // Therefore a manual set here is preferred as a tradeoff with a better runtime later when often calling the aforementioned function
        virtual_address_space.map_physical_region(region.descriptor, region.descriptor.address.to_virtual_address_with_offset(higher_half_direct_map.value), .{
            .write = true,
            .user = true,
        }, physical_address_space.page_size);
    }
    log.debug("Mapped usable", .{});

    // TODO: better flags
    for (physical_address_space.reclaimable) |region| {
        // This needs an specific offset since the kernel value "higher_half_direct_map" is not set yet. The to_higher_half_virtual_address() function depends on this value being set.
        // Therefore a manual set here is preferred as a tradeoff with a better runtime later when often calling the aforementioned function
        virtual_address_space.map_physical_region(region.descriptor, region.descriptor.address.to_virtual_address_with_offset(higher_half_direct_map.value), .{
            .write = true,
            .user = true,
        }, physical_address_space.page_size);
    }
    log.debug("Mapped reclaimable", .{});

    // TODO: better flags
    for (physical_address_space.framebuffer) |region| {
        // This needs an specific offset since the kernel value "higher_half_direct_map" is not set yet. The to_higher_half_virtual_address() function depends on this value being set.
        // Therefore a manual set here is preferred as a tradeoff with a better runtime later when often calling the aforementioned function
        virtual_address_space.map_physical_region(region, region.address.to_virtual_address_with_offset(higher_half_direct_map.value), .{
            .write = true,
            .user = true,
        }, physical_address_space.page_size);
    }
    log.debug("Mapped framebuffer", .{});

    virtual_address_space.make_current();
    @import("root").higher_half_direct_map = higher_half_direct_map;
    log.debug("Higher half map: 0x{x}", .{higher_half_direct_map.value});
    // Update identity-mapped pointers to higher-half ones
    physical_address_space.usable.ptr = @intToPtr(@TypeOf(physical_address_space.usable.ptr), @ptrToInt(physical_address_space.usable.ptr) + higher_half_direct_map.value);
    physical_address_space.reclaimable.ptr = @intToPtr(@TypeOf(physical_address_space.reclaimable.ptr), @ptrToInt(physical_address_space.reclaimable.ptr) + higher_half_direct_map.value);
    physical_address_space.framebuffer.ptr = @intToPtr(@TypeOf(physical_address_space.framebuffer.ptr), @ptrToInt(physical_address_space.framebuffer.ptr) + higher_half_direct_map.value);
    physical_address_space.reserved.ptr = @intToPtr(@TypeOf(physical_address_space.reserved.ptr), @ptrToInt(physical_address_space.reserved.ptr) + higher_half_direct_map.value);
    physical_address_space.kernel_and_modules.ptr = @intToPtr(@TypeOf(physical_address_space.kernel_and_modules.ptr), @ptrToInt(physical_address_space.kernel_and_modules.ptr) + higher_half_direct_map.value);
    log.debug("Memory mapping initialized!", .{});

    for (physical_address_space.reclaimable) |*region| {
        const bitset = region.get_bitset_extended(physical_address_space.page_size);
        const bitset_size = bitset.len * @sizeOf(PhysicalAddressSpace.MapEntry.BitsetBaseType);
        region.allocated_size = common.align_forward(bitset_size, physical_address_space.page_size);
        region.setup_bitset(physical_address_space.page_size);
    }

    const old_reclaimable = physical_address_space.reclaimable.len;
    physical_address_space.usable.len += old_reclaimable;
    physical_address_space.reclaimable.len = 0;

    log.debug("Reclaimed reclaimable physical memory. Counting with {} more regions", .{old_reclaimable});

    // TODO: Handle virtual memory management later on

    //if (true) @panic("this is going to corrupt memory since this is on the stack right now", .{});

    //var insertion_result = false;
    //insertion_result = virtual_address_space.free_regions_by_address.insert(&kernel.memory_region.item_address, &kernel.memory_region, kernel.memory_region.address.value, .panic);
    //common.runtime_assert(@src(), insertion_result);
    //insertion_result = virtual_address_space.free_regions_by_size.insert(&kernel.memory_region.item_size, &kernel.memory_region, kernel.memory_region.size, .allow);
    //common.runtime_assert(@src(), insertion_result);
    //log.debug("Set root for Virtual Memory Manager tree", .{});
    //log.debug("Tree address (free/addr): 0x{x}", .{@ptrToInt(&virtual_address_space.free_regions_by_address)});
    //log.debug("Tree address (free/size): 0x{x}", .{@ptrToInt(&virtual_address_space.free_regions_by_size)});
    //log.debug("Tree address (used): 0x{x}", .{@ptrToInt(&virtual_address_space.used_regions)});

    //for (kernel.physical_address_space.usable) |physical_entry| {
    //virtual_address_space.integrate_mapped_physical_entry(physical_entry, physical_entry.descriptor.address.to_higher_half_virtual_address()) catch @panic("unable to integrate physical region into vmm");
    //}
    //log.debug("Finished the integration of usable regions into the kernel address space successfully!", .{});
    //for (kernel.physical_address_space.framebuffer) |physical_region| {
    //virtual_address_space.integrate_mapped_physical_region(physical_region, physical_region.address.to_higher_half_virtual_address()) catch @panic("unable to integrate physical region into vmm");
    //}
    //log.debug("Finished the integration of framebuffer regions into the kernel address space successfully!", .{});
    //for (kernel.physical_address_space.usable) |physical_entry| {
    //log.debug("(0x{x},\t0x{x}) - 0x{x}", .{ physical_entry.descriptor.address.value, physical_entry.descriptor.address.value + physical_entry.descriptor.size, physical_entry.descriptor.address.value + physical_entry.allocated_size });
    //}
    log.debug("Paging initialized", .{});

    return virtual_address_space;
}

pub const VirtualAddressSpace = struct {
    cr3: u64 = 0,
    cpu_features: x86_64.CPUFeatures,
    physical_address_space: *common.PhysicalAddressSpace,

    const Indices = [common.enum_values(PageIndex).len]u16;

    pub inline fn new(physical_address_space: *PhysicalAddressSpace, cpu_features: common.arch.CPUFeatures) ?VirtualAddressSpace {
        const page_count = common.bytes_to_pages(@sizeOf(PML4Table), physical_address_space.page_size, .must_be_exact);
        const cr3_physical_address = physical_address_space.allocate(page_count) orelse return null;
        const virtual_address_space = VirtualAddressSpace{
            .cr3 = cr3_physical_address.value,
            .cpu_features = cpu_features,
            .physical_address_space = physical_address_space,
        };

        common.zero(virtual_address_space.get_pml4().access_kernel([*]u8)[0..@sizeOf(PML4Table)]);
        return virtual_address_space;
    }

    pub inline fn bootstrapping(cpu_features: x86_64.CPUFeatures, physical_address_space: *PhysicalAddressSpace) VirtualAddressSpace {
        return VirtualAddressSpace{
            .cr3 = x86_64.cr3.read_raw(),
            .cpu_features = cpu_features,
            .physical_address_space = physical_address_space,
        };
    }

    pub inline fn from_context(context: anytype) VirtualAddressSpace {
        // This is taking a u64 instead of a physical address to easily put here the value of the CR3 register
        comptime common.comptime_assert(@TypeOf(context) == u64);
        const cr3 = context;
        return VirtualAddressSpace{
            .cr3 = cr3,
        };
    }

    pub fn get_pml4(address_space: VirtualAddressSpace) PhysicalAddress {
        return PhysicalAddress.new(address_space.cr3);
    }

    pub fn map_kernel_address_space_higher_half(address_space: VirtualAddressSpace) void {
        _ = address_space;
        TODO(@src());
        //const cr3 = address_space.cr3;
        //// TODO: proper address
        //const cr3_physical_address = PhysicalAddress.new(cr3);
        //const cr3_virtual_address = cr3_physical_address.to_higher_half_virtual_address();
        //kernel.virtual_address_space.map(cr3_physical_address, cr3_virtual_address, common.VirtualAddressSpace.Flags.from_flags(&.{ .read_write, .user }));
        //const pml4 = cr3_virtual_address.access(*PML4Table);
        //common.zero_slice(pml4[0..0x100]);
        //common.copy(PML4E, pml4[0x100..], PhysicalAddress.new(kernel.virtual_address_space.arch.cr3).access_higher_half(*PML4Table)[0x100..]);
        //log.debug("USER CR3: 0x{x}", .{cr3_physical_address.value});
    }

    pub fn map(arch_address_space: *VirtualAddressSpace, physical_address: PhysicalAddress, virtual_address: VirtualAddress, flags: VirtualAddressSpace.Flags) void {
        if (should_log) log.debug("Init mapping", .{});
        common.runtime_assert(@src(), common.is_aligned(virtual_address.value, arch_address_space.cpu_features.page_size));
        common.runtime_assert(@src(), common.is_aligned(physical_address.value, arch_address_space.cpu_features.page_size));

        const indices = compute_indices(virtual_address);

        var pdp: *volatile PDPTable = undefined;
        {
            var pml4 = arch_address_space.get_pml4().access_kernel(*PML4Table);
            var pml4_entry = &pml4[indices[@enumToInt(PageIndex.PML4)]];
            var pml4_entry_value = pml4_entry.value;

            if (pml4_entry_value.contains(.present)) {
                pdp = get_address_from_entry_bits(pml4_entry_value.bits, arch_address_space.cpu_features).access_kernel(@TypeOf(pdp));
            } else {
                const pdp_allocation = arch_address_space.physical_address_space.allocate(common.bytes_to_pages(@sizeOf(PDPTable), arch_address_space.physical_address_space.page_size, .must_be_exact)) orelse @panic("unable to alloc pdp");
                pdp = pdp_allocation.access_kernel(@TypeOf(pdp));
                pdp.* = common.zeroes(PDPTable);
                pml4_entry_value.or_flag(.present);
                pml4_entry_value.or_flag(.read_write);
                pml4_entry_value.or_flag(.user);
                pml4_entry_value.bits = set_entry_in_address_bits(pml4_entry_value.bits, pdp_allocation, arch_address_space.cpu_features);
                pml4_entry.value = pml4_entry_value;
            }
        }

        if (should_log) log.debug("PDP", .{});

        var pd: *volatile PDTable = undefined;
        {
            var pdp_entry = &pdp[indices[@enumToInt(PageIndex.PDP)]];
            var pdp_entry_value = pdp_entry.value;

            if (pdp_entry_value.contains(.present)) {
                pd = get_address_from_entry_bits(pdp_entry_value.bits, arch_address_space.cpu_features).access_kernel(@TypeOf(pd));
            } else {
                const pd_allocation = arch_address_space.physical_address_space.allocate(common.bytes_to_pages(@sizeOf(PDTable), arch_address_space.physical_address_space.page_size, .must_be_exact)) orelse @panic("unable to alloc pd");
                pd = pd_allocation.access_kernel(@TypeOf(pd));
                pd.* = common.zeroes(PDTable);
                pdp_entry_value.or_flag(.present);
                pdp_entry_value.or_flag(.read_write);
                pdp_entry_value.or_flag(.user);
                pdp_entry_value.bits = set_entry_in_address_bits(pdp_entry_value.bits, pd_allocation, arch_address_space.cpu_features);
                pdp_entry.value = pdp_entry_value;
            }
        }

        var pt: *volatile PTable = undefined;
        {
            var pd_entry = &pd[indices[@enumToInt(PageIndex.PD)]];
            var pd_entry_value = pd_entry.value;

            if (pd_entry_value.contains(.present)) {
                pt = get_address_from_entry_bits(pd_entry_value.bits, arch_address_space.cpu_features).access_kernel(@TypeOf(pt));
            } else {
                const pt_allocation = arch_address_space.physical_address_space.allocate(common.bytes_to_pages(@sizeOf(PTable), arch_address_space.physical_address_space.page_size, .must_be_exact)) orelse @panic("unable to alloc pt");
                pt = pt_allocation.access_kernel(@TypeOf(pt));
                pt.* = common.zeroes(PTable);
                pd_entry_value.or_flag(.present);
                pd_entry_value.or_flag(.read_write);
                pd_entry_value.or_flag(.user);
                pd_entry_value.bits = set_entry_in_address_bits(pd_entry_value.bits, pt_allocation, arch_address_space.cpu_features);
                pd_entry.value = pd_entry_value;
            }
        }

        pt[indices[@enumToInt(PageIndex.PT)]] = blk: {
            var pte = PTE{
                .value = PTE.Flags.from_bits(flags.bits),
            };
            pte.value.or_flag(.present);
            pte.value.bits = set_entry_in_address_bits(pte.value.bits, physical_address, arch_address_space.cpu_features);

            break :blk pte;
        };

        if (should_log) log.debug("Ended mapping", .{});
    }

    pub fn translate_address(address_space: *VirtualAddressSpace, asked_virtual_address: VirtualAddress) ?PhysicalAddress {
        common.runtime_assert(@src(), asked_virtual_address.is_valid());
        const virtual_address = asked_virtual_address.aligned_backward(address_space.physical_address_space.page_size);

        const indices = compute_indices(virtual_address);

        var pdp: *volatile PDPTable = undefined;
        {
            //log.debug("CR3: 0x{x}", .{address_space.cr3});
            var pml4 = address_space.get_pml4().access_kernel(*PML4Table);
            const pml4_entry = &pml4[indices[@enumToInt(PageIndex.PML4)]];
            var pml4_entry_value = pml4_entry.value;

            if (!pml4_entry_value.contains(.present)) return null;
            //log.debug("PML4 present", .{});

            pdp = get_address_from_entry_bits(pml4_entry_value.bits, address_space.cpu_features).access_kernel(@TypeOf(pdp));
        }
        if (should_log) log.debug("PDP", .{});

        var pd: *volatile PDTable = undefined;
        {
            var pdp_entry = &pdp[indices[@enumToInt(PageIndex.PDP)]];
            var pdp_entry_value = pdp_entry.value;

            if (!pdp_entry_value.contains(.present)) return null;
            //log.debug("PDP present", .{});

            pd = get_address_from_entry_bits(pdp_entry_value.bits, address_space.cpu_features).access_kernel(@TypeOf(pd));
        }
        if (should_log) log.debug("PD", .{});

        var pt: *volatile PTable = undefined;
        {
            var pd_entry = &pd[indices[@enumToInt(PageIndex.PD)]];
            var pd_entry_value = pd_entry.value;

            if (!pd_entry_value.contains(.present)) return null;
            //log.debug("PD present", .{});

            pt = get_address_from_entry_bits(pd_entry_value.bits, address_space.cpu_features).access_kernel(@TypeOf(pt));
        }
        if (should_log) log.debug("PT", .{});

        const pte = pt[indices[@enumToInt(PageIndex.PT)]];
        if (!pte.value.contains(.present)) return null;

        const base_physical_address = get_address_from_entry_bits(pte.value.bits, address_space.cpu_features);
        const offset = asked_virtual_address.value - virtual_address.value;
        if (offset != 0) @panic("lol");

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

    pub fn make_current(address_space: *VirtualAddressSpace) void {
        log.debug("Applying address space: 0x{x}", .{address_space.cr3});
        x86_64.cr3.write_raw(address_space.cr3);
        log.debug("Applied address space: 0x{x}", .{address_space.cr3});
    }

    pub inline fn new_flags(general_flags: common.VirtualAddressSpace.Flags) Flags {
        var flags = Flags.empty();
        if (general_flags.write) flags.or_flag(.read_write);
        if (general_flags.user) flags.or_flag(.user);
        if (general_flags.cache_disable) flags.or_flag(.cache_disable);
        if (general_flags.accessed) flags.or_flag(.accessed);
        if (!general_flags.execute) flags.or_flag(.execute_disable);
        return flags;
    }

    // TODO:
    pub const Flags = common.Bitflag(true, enum(u64) {
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
};

const address_mask: u64 = 0x000000fffffff000;
fn set_entry_in_address_bits(old_entry_value: u64, new_address: PhysicalAddress, cpu_features: x86_64.CPUFeatures) u64 {
    common.runtime_assert(@src(), cpu_features.physical_address_max_bit == 40);
    common.runtime_assert(@src(), common.is_aligned(new_address.value, cpu_features.page_size));
    const address_masked = new_address.value & address_mask;
    const old_entry_value_masked = old_entry_value & ~address_masked;
    const result = address_masked | old_entry_value_masked;
    return result;
}

fn get_address_from_entry_bits(entry_bits: u64, cpu_features: x86_64.CPUFeatures) PhysicalAddress {
    common.runtime_assert(@src(), cpu_features.physical_address_max_bit == 40);
    const address = entry_bits & address_mask;
    common.runtime_assert(@src(), common.is_aligned(address, cpu_features.page_size));

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

    const Flags = common.Bitflag(true, enum(u64) {
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

    const Flags = common.Bitflag(true, enum(u64) {
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

    const Flags = common.Bitflag(true, enum(u64) {
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

    const Flags = common.Bitflag(true, enum(u64) {
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

// Paging behavior is controlled by the following control bits:
// • The WP and PG flags in control register CR0 (bit 16 and bit 31, respectively).
// • The PSE, PAE, PGE, LA57, PCIDE, SMEP, SMAP, PKE, CET, and PKS flags in control register CR4 (bit 4, bit 5, bit 7, bit 12, bit 17, bit 20, bit 21, bit 22, bit 23, and bit 24, respectively).
// • The LME and NXE flags in the IA32_EFER MSR (bit 8 and bit 11, respectively).
// • The AC flag in the EFLAGS register (bit 18).
// • The “enable HLAT” VM-execution control (tertiary processor-based VM-execution control bit 1; see Section 24.6.2, “Processor-Based VM-Execution Controls,” in the Intel® 64 and IA-32 Architectures Software Developer’s Manual, Volume 3C).

const common = @import("../../../common.zig");
const context = @import("context");
const root = @import("root");

const x86_64 = common.arch.x86_64;

const TODO = common.TODO;
const log = common.log.scoped(.Paging_x86_64);
const Allocator = common.Allocator;
const VirtualAddress = common.VirtualAddress;
const VirtualMemoryRegion = common.VirtualMemoryRegion;
const PhysicalAddress = common.PhysicalAddress;
const PhysicalAddressSpace = common.PhysicalAddressSpace;

pub var should_log = false;

pub fn init(kernel_virtual_address_space: *common.VirtualAddressSpace, physical_address_space: *PhysicalAddressSpace, stivale_pmrs: []x86_64.Stivale2.Struct.PMRs.PMR, cached_higher_half_direct_map: u64) void {
    log.debug("About to dereference memory regions", .{});
    var new_virtual_address_space: common.VirtualAddressSpace = undefined;
    common.VirtualAddressSpace.initialize_kernel_address_space(&new_virtual_address_space, physical_address_space) orelse @panic("unable to initialize kernel address space");

    // Map the kernel and do some tests
    {
        // TODO: better flags
        for (stivale_pmrs) |pmr| {
            const section_virtual_address = VirtualAddress.new(pmr.address);
            const kernel_section_virtual_region = VirtualMemoryRegion.new(section_virtual_address, pmr.size);
            const section_physical_address = kernel_virtual_address_space.translate_address(section_virtual_address) orelse @panic("address not translated");
            new_virtual_address_space.map_virtual_region(kernel_section_virtual_region, section_physical_address, .{
                .execute = pmr.permissions & x86_64.Stivale2.Struct.PMRs.PMR.executable != 0,
                .write = true, //const writable = permissions & x86_64.Stivale2.Struct.PMRs.PMR.writable != 0;
            });
        }
    }

    // TODO: better flags
    for (physical_address_space.usable) |region| {
        // This needs an specific offset since the kernel value "higher_half_direct_map" is not set yet. The to_higher_half_virtual_address() function depends on this value being set.
        // Therefore a manual set here is preferred as a tradeoff with a better runtime later when often calling the aforementioned function
        new_virtual_address_space.map_physical_region(region.descriptor, region.descriptor.address.to_virtual_address_with_offset(cached_higher_half_direct_map), .{
            .write = true,
            .user = true,
        });
    }
    log.debug("Mapped usable", .{});

    // TODO: better flags
    for (physical_address_space.reclaimable) |region| {
        // This needs an specific offset since the kernel value "higher_half_direct_map" is not set yet. The to_higher_half_virtual_address() function depends on this value being set.
        // Therefore a manual set here is preferred as a tradeoff with a better runtime later when often calling the aforementioned function
        new_virtual_address_space.map_physical_region(region.descriptor, region.descriptor.address.to_virtual_address_with_offset(cached_higher_half_direct_map), .{
            .write = true,
            .user = true,
        });
    }
    log.debug("Mapped reclaimable", .{});

    // TODO: better flags
    for (physical_address_space.framebuffer) |region| {
        // This needs an specific offset since the kernel value "higher_half_direct_map" is not set yet. The to_higher_half_virtual_address() function depends on this value being set.
        // Therefore a manual set here is preferred as a tradeoff with a better runtime later when often calling the aforementioned function
        new_virtual_address_space.map_physical_region(region, region.address.to_virtual_address_with_offset(cached_higher_half_direct_map), .{
            .write = true,
            .user = true,
        });
    }
    log.debug("Mapped framebuffer", .{});

    new_virtual_address_space.make_current();
    new_virtual_address_space.copy(kernel_virtual_address_space);
    @import("root").higher_half_direct_map = VirtualAddress.new(cached_higher_half_direct_map);
    // Update identity-mapped pointers to higher-half ones
    physical_address_space.usable.ptr = @intToPtr(@TypeOf(physical_address_space.usable.ptr), @ptrToInt(physical_address_space.usable.ptr) + cached_higher_half_direct_map);
    physical_address_space.reclaimable.ptr = @intToPtr(@TypeOf(physical_address_space.reclaimable.ptr), @ptrToInt(physical_address_space.reclaimable.ptr) + cached_higher_half_direct_map);
    physical_address_space.framebuffer.ptr = @intToPtr(@TypeOf(physical_address_space.framebuffer.ptr), @ptrToInt(physical_address_space.framebuffer.ptr) + cached_higher_half_direct_map);
    physical_address_space.reserved.ptr = @intToPtr(@TypeOf(physical_address_space.reserved.ptr), @ptrToInt(physical_address_space.reserved.ptr) + cached_higher_half_direct_map);
    physical_address_space.kernel_and_modules.ptr = @intToPtr(@TypeOf(physical_address_space.kernel_and_modules.ptr), @ptrToInt(physical_address_space.kernel_and_modules.ptr) + cached_higher_half_direct_map);
    log.debug("Memory mapping initialized!", .{});

    for (physical_address_space.reclaimable) |*region| {
        const bitset = region.get_bitset_extended(context.page_size);
        const bitset_size = bitset.len * @sizeOf(PhysicalAddressSpace.MapEntry.BitsetBaseType);
        region.allocated_size = common.align_forward(bitset_size, context.page_size);
        region.setup_bitset(context.page_size);
    }

    const old_reclaimable = physical_address_space.reclaimable.len;
    physical_address_space.usable.len += old_reclaimable;
    physical_address_space.reclaimable.len = 0;

    log.debug("Reclaimed reclaimable physical memory. Counting with {} more regions", .{old_reclaimable});

    // TODO: Handle virtual memory management later on

    log.debug("Paging initialized", .{});
}

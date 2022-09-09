const std = @import("../../../../../common/std.zig");

const CPUID = @import("../../../../../common/arch/x86_64/cpuid.zig");
const crash = @import("../../../../crash.zig");
const drivers = @import("../../drivers.zig");
const Graphics = @import("../../../../../drivers/graphics.zig");
const Heap = @import("../../../../heap.zig");
const kernel = @import("../../../../kernel.zig");
const main = @import("../../../../main.zig").main;
const PhysicalAddress = @import("../../../../physical_address.zig");
const Spinlock = @import("../../../../spinlock.zig");
const TLS = @import("../../tls.zig");
const Timer = @import("../../../../timer.zig");
const VAS = @import("../../vas.zig");
const VirtualAddressSpace = @import("../../../../virtual_address_space.zig");
const x86_64 = @import("../../../common.zig");
const default_logger = @import("../../../../log.zig");
const stivale_log = std.log.scoped(.Stivale);

//const std = @import("../../../../../common/std.zig");

const common = @import("../../../../common.zig");
const Context = @import("../../context.zig");
//const context_switch = @import("../../context_switch.zig");
const CPU = @import("../../cpu.zig");
//const crash = @import("../../../../crash.zig");
//const kernel = @import("../../../../kernel.zig");
const stivale = @import("header.zig");
//const x86_64 = @import("../../common.zig");
const VirtualAddress = @import("../../../../virtual_address.zig");
//const VirtualAddressSpace = @import("../../../../virtual_address_space.zig");
const VirtualMemoryRegion = @import("../../../../virtual_memory_region.zig");
//const PhysicalAddress = @import("../../../../physical_address.zig");
const PhysicalAddressSpace = @import("../../../../physical_address_space.zig");
const PhysicalMemoryRegion = @import("../../../../physical_memory_region.zig");
const Scheduler = @import("../../../../scheduler.zig");
//const SegmentedList = @import("../../../../../common/list.zig").SegmentedList;
const Thread = @import("../../../../thread.zig");
//const TLS = @import("../../tls.zig");

const FileInMemory = common.FileInMemory;
const Framebuffer = common.Framebuffer;
const page_size = x86_64.page_size;
//const log = std.log.scoped(.stivale);
const Struct = stivale.Struct;
const TODO = crash.TODO;
const Allocator = std.Allocator;

pub export fn kernel_entry_point(stivale2_struct_address: u64) callconv(.C) noreturn {
    // Start a timer to count the CPU cycles the entry point function takes
    var entry_point_timer = Timer.Scoped(.EntryPoint).start();
    // Get maximum physical address information
    x86_64.max_physical_address_bit = CPUID.get_max_physical_address_bit();
    // Generate enough bootstraping structures to make some early stuff work
    var bootstrap_context = std.zeroes(BootstrapContext);
    {
        bootstrap_context.cpu.id = 0;
        TLS.preset_bsp(&kernel.scheduler, &bootstrap_context.thread, &bootstrap_context.cpu);
        bootstrap_context.thread.context = &bootstrap_context.context;

        // @ZigBug: @ptrCast here crashes the compiler
        kernel.scheduler.cpus = @intToPtr([*]CPU, @ptrToInt(&bootstrap_context.cpu))[0..1];
    }

    stivale_log.debug("Hello kernel!", .{});
    stivale_log.debug("Stivale2 address: 0x{x}", .{stivale2_struct_address});

    const stivale2_struct_physical_address = PhysicalAddress.new(stivale2_struct_address);
    // In here all the memory but the kernel is identity-mapped, so we can get away with this
    var stivale2_struct = @intToPtr(*Struct, stivale2_struct_physical_address.value);
    // This is just a cached version, not the global one (which is set after kernel address space initialization)
    const higher_half_direct_map = blk: {
        const hhdm_struct = find(Struct.HHDM, stivale2_struct) orelse @panic("Unable to find higher half direct map struct");
        stivale_log.debug("HHDM: 0x{x}", .{hhdm_struct.addr});
        if (hhdm_struct.addr == 0) {
            @panic("Received 0 as the higher half address");
        }

        break :blk hhdm_struct.addr;
    };

    x86_64.rsdp_physical_address = blk: {
        const rsdp_struct = find(stivale.Struct.RSDP, stivale2_struct) orelse @panic("Unable to find RSDP struct");
        const rsdp = rsdp_struct.rsdp;
        if (rsdp == 0) @panic("Received 0 as RSDP struct");
        stivale_log.debug("RSDP struct: 0x{x}", .{rsdp});
        break :blk rsdp;
    };

    kernel.physical_address_space = blk: {
        var timer = Timer.Scoped(.PhysicalAddressSpaceInitialization).start();
        defer timer.end_and_log();

        const memory_map_struct = find(Struct.MemoryMap, stivale2_struct) orelse @panic("Unable to find memory map struct");
        const memory_map_entries = memory_map_struct.memmap()[0..memory_map_struct.entry_count];
        var result = PhysicalAddressSpace{};

        // First, it is required to find a spot in memory big enough to host all the memory map entries in a architecture-independent and bootloader-independent way. This is the host entry
        const host_entry = host_entry_blk: {
            for (memory_map_entries) |*entry| {
                if (entry.type == .usable) {
                    const bitset = PhysicalAddressSpace.MapEntry.get_bitset_from_address_and_size(PhysicalAddress.new(entry.address), entry.size, 0);
                    const bitset_size = bitset.len * @sizeOf(PhysicalAddressSpace.MapEntry.BitsetBaseType);
                    // INFO: this is separated since the bitset needs to be in a different page than the memory map
                    const bitset_page_count = std.div_ceil(u64, bitset_size, page_size) catch unreachable;
                    // Allocate a bit more memory than needed just in case
                    const memory_map_allocation_size = memory_map_struct.entry_count * @sizeOf(PhysicalAddressSpace.MapEntry);
                    const memory_map_page_count = std.div_ceil(u64, memory_map_allocation_size, page_size) catch unreachable;
                    const total_allocated_page_count = bitset_page_count + memory_map_page_count;
                    const total_allocation_size = page_size * total_allocated_page_count;
                    std.assert(entry.size > total_allocation_size);
                    result.usable = @intToPtr([*]PhysicalAddressSpace.MapEntry, entry.address + std.align_forward(bitset_size, page_size))[0..1];
                    var block = &result.usable[0];
                    block.* = PhysicalAddressSpace.MapEntry{
                        .descriptor = PhysicalMemoryRegion{
                            .address = PhysicalAddress.new(entry.address),
                            .size = entry.size,
                        },
                        .allocated_size = total_allocation_size,
                        .type = .usable,
                    };

                    const virtual_address_offset = 0;
                    block.setup_bitset(virtual_address_offset);

                    std.log.scoped(.Physical).debug("Usable physical region: (0x{x}, 0x{x})", .{ block.descriptor.address.value, block.descriptor.address.offset(block.descriptor.size).value });

                    break :host_entry_blk block;
                }
            }

            @panic("There is no memory map entry big enough to store the memory map entries");
        };

        // The counter starts with one because we have already filled the memory map with the host entry
        for (memory_map_entries) |*entry| {
            if (entry.type == .usable) {
                if (entry.address == host_entry.descriptor.address.value) continue;

                const index = result.usable.len;
                result.usable.len += 1;
                var result_entry = &result.usable[index];
                result_entry.* = PhysicalAddressSpace.MapEntry{
                    .descriptor = PhysicalMemoryRegion{
                        .address = PhysicalAddress.new(entry.address),
                        .size = entry.size,
                    },
                    .allocated_size = 0,
                    .type = .usable,
                };

                std.log.scoped(.Physical).debug("Usable physical region: (0x{x}, 0x{x})", .{ result_entry.descriptor.address.value, result_entry.descriptor.address.offset(result_entry.descriptor.size).value });

                const virtual_address_offset = 0;
                const bitset = result_entry.get_bitset_extended(virtual_address_offset);
                const bitset_size = bitset.len * @sizeOf(PhysicalAddressSpace.MapEntry.BitsetBaseType);
                result_entry.allocated_size = std.align_forward(bitset_size, page_size);
                result_entry.setup_bitset(virtual_address_offset);
            }
        }

        result.reclaimable.ptr = @intToPtr(@TypeOf(result.reclaimable.ptr), @ptrToInt(result.usable.ptr) + (@sizeOf(PhysicalAddressSpace.MapEntry) * result.usable.len));

        for (memory_map_entries) |*entry| {
            if (entry.type == .bootloader_reclaimable) {
                const index = result.reclaimable.len;
                result.reclaimable.len += 1;
                var result_entry = &result.reclaimable[index];
                result_entry.* = PhysicalAddressSpace.MapEntry{
                    .descriptor = PhysicalMemoryRegion{
                        .address = PhysicalAddress.new(entry.address),
                        .size = entry.size,
                    },
                    .allocated_size = 0,
                    .type = .reclaimable,
                };

                std.log.scoped(.Physical).debug("Framebuffer physical region: (0x{x}, 0x{x})", .{ result_entry.descriptor.address.value, result_entry.descriptor.address.offset(result_entry.descriptor.size).value });

                // Don't use the bitset here because it would imply using memory that may not be usable at the moment of writing the bitset to this region
            }
        }

        result.framebuffer.ptr = @intToPtr(@TypeOf(result.framebuffer.ptr), @ptrToInt(result.reclaimable.ptr) + (@sizeOf(PhysicalAddressSpace.MapEntry) * result.reclaimable.len));

        for (memory_map_entries) |*entry| {
            if (entry.type == .framebuffer) {
                const index = result.framebuffer.len;
                result.framebuffer.len += 1;
                var result_entry = &result.framebuffer[index];
                result_entry.* = PhysicalMemoryRegion{
                    .address = PhysicalAddress.new(entry.address),
                    .size = entry.size,
                };

                std.log.scoped(.Physical).debug("Framebuffer physical region: (0x{x}, 0x{x})", .{ result_entry.address.value, result_entry.address.offset(result_entry.size).value });

                // Don't use the bitset here because it would imply using memory that may not be usable at the moment of writing the bitset to this region
            }
        }

        {
            const framebuffer_size = @sizeOf(PhysicalMemoryRegion) * result.framebuffer.len;
            const kernel_and_modules_slice_address = @ptrToInt(result.framebuffer.ptr) + framebuffer_size;
            result.kernel_and_modules.ptr = @intToPtr([*]PhysicalMemoryRegion, kernel_and_modules_slice_address);
        }

        for (memory_map_entries) |*entry| {
            if (entry.type == .kernel_and_modules) {
                const index = result.kernel_and_modules.len;
                result.kernel_and_modules.len += 1;
                var result_entry = &result.kernel_and_modules[index];
                result_entry.* = PhysicalMemoryRegion{
                    .address = PhysicalAddress.new(entry.address),
                    .size = entry.size,
                };

                std.log.scoped(.Physical).debug("Kernel physical region: (0x{x}, 0x{x})", .{ result_entry.address.value, result_entry.address.offset(result_entry.size).value });

                // Don't use the bitset here because it would imply using memory that may not be usable at the moment of writing the bitset to this region
            }
        }

        {
            std.assert(result.kernel_and_modules.len == 1);
            const kernels_and_modules_size = @sizeOf(PhysicalMemoryRegion) * result.kernel_and_modules.len;
            const reserved_slice_address = @ptrToInt(result.kernel_and_modules.ptr) + kernels_and_modules_size;
            result.reserved.ptr = @intToPtr([*]PhysicalMemoryRegion, reserved_slice_address);
        }

        for (memory_map_entries) |*entry| {
            if (entry.type == .reserved) {
                const index = result.reserved.len;
                result.reserved.len += 1;
                var result_entry = &result.reserved[index];
                result_entry.* = PhysicalMemoryRegion{
                    .address = PhysicalAddress.new(entry.address),
                    .size = entry.size,
                };
                std.log.scoped(.Physical).debug("Reserved physical region: (0x{x}, 0x{x})", .{ result_entry.address.value, result_entry.address.offset(result_entry.size).value });

                // Don't use the bitset here because it would imply using memory that may not be usable at the moment of writing the bitset to this region
            }
        }

        stivale_log.debug("Memory map initialized", .{});
        break :blk result;
    };

    // Init paging
    {
        var timer = Timer.Scoped(.VirtualAddressSpaceInitialization).start();
        defer timer.end_and_log();

        // Kernel address space initialization
        kernel.bootstrap_virtual_address_space = kernel.bootstrap_allocator.allocator().create(VirtualAddressSpace) catch @panic("bootstrap allocator failed");
        VirtualAddressSpace.from_current(kernel.bootstrap_virtual_address_space);
        kernel.virtual_address_space = VirtualAddressSpace{
            .arch = .{},
            .privilege_level = .kernel,
            .heap = Heap.new(&kernel.virtual_address_space),
            .lock = Spinlock{},
        };
        VAS.new(&kernel.virtual_address_space, &kernel.physical_address_space, higher_half_direct_map);

        // Get protected memory regions from the bootloader
        const stivale_pmrs_struct = find(Struct.PMRs, stivale2_struct) orelse @panic("Unable to find Stivale PMRs");
        const stivale_pmrs = stivale_pmrs_struct.pmrs()[0..stivale_pmrs_struct.entry_count];

        // Map the kernel and do some tests
        {
            std.log.scoped(.MyMap).debug("Starting mapping kernel executable", .{});

            var map_timer = Timer.Scoped(.KernelMap).start();
            defer map_timer.end_and_log();

            // TODO: better flags
            for (stivale_pmrs) |pmr| {
                defer std.log.scoped(.MyMap).debug("Mapped section", .{});
                const section_virtual_address = VirtualAddress.new(pmr.address);
                const section_page_count = @divExact(pmr.size, x86_64.page_size);
                const section_physical_address = kernel.bootstrap_virtual_address_space.translate_address(section_virtual_address) orelse @panic("address not translated");
                kernel.virtual_address_space.map_extended(section_physical_address, section_virtual_address, section_page_count, .{
                    .execute = pmr.permissions & Struct.PMRs.PMR.executable != 0,
                    .write = true, //const writable = permissions & Stivale2.Struct.PMRs.PMR.writable != 0;
                }, .no, true, higher_half_direct_map) catch unreachable;
            }
        }

        var mapping_pages_mapped = x86_64.VAS.bootstrapping_physical_addresses.items.len;
        {
            std.log.scoped(.MyMap).debug("Starting mapping usable regions", .{});

            var map_timer = Timer.Scoped(.UsableMap).start();
            defer map_timer.end_and_log();
            // TODO: better flags
            for (kernel.physical_address_space.usable) |region| {
                // This needs an specific offset since the kernel value "higher_half_direct_map" is not set yet. The to_higher_half_virtual_address() function depends on this value being set.
                // Therefore a manual set here is preferred as a tradeoff with a better runtime later when often calling the aforementioned function
                const physical_address = region.descriptor.address;
                const virtual_address = region.descriptor.address.to_virtual_address_with_offset(higher_half_direct_map);
                const page_count = @divExact(region.allocated_size, x86_64.page_size);
                std.log.scoped(.Mappppp).debug("Mapping (0x{x}, 0x{x}) to (0x{x}, 0x{x})", .{ physical_address.value, physical_address.offset(region.allocated_size).value, virtual_address.value, virtual_address.offset(region.allocated_size).value });
                kernel.virtual_address_space.map_extended(physical_address, virtual_address, page_count, .{
                    .write = true,
                    .user = true,
                }, .no, true, higher_half_direct_map) catch unreachable;
            }
        }

        {
            var map_timer = Timer.Scoped(.ReclaimableMap).start();
            defer map_timer.end_and_log();
            // TODO: better flags
            for (kernel.physical_address_space.reclaimable) |region| {
                // This needs an specific offset since the kernel value "higher_half_direct_map" is not set yet. The to_higher_half_virtual_address() function depends on this value being set.
                // Therefore a manual set here is preferred as a tradeoff with a better runtime later when often calling the aforementioned function
                std.assert(std.is_aligned(region.descriptor.size, x86_64.page_size));
                kernel.virtual_address_space.map_extended(region.descriptor.address, region.descriptor.address.to_virtual_address_with_offset(higher_half_direct_map), region.descriptor.size / x86_64.page_size, .{
                    .write = true,
                    .user = true,
                }, .no, true, higher_half_direct_map) catch unreachable;
            }
        }

        {
            var map_timer = Timer.Scoped(.Framebuffer).start();
            defer map_timer.end_and_log();
            // TODO: better flags
            for (kernel.physical_address_space.framebuffer) |region| {
                // This needs an specific offset since the kernel value "higher_half_direct_map" is not set yet. The to_higher_half_virtual_address() function depends on this value being set.
                // Therefore a manual set here is preferred as a tradeoff with a better runtime later when often calling the aforementioned function
                std.assert(std.is_aligned(region.size, x86_64.page_size));
                kernel.virtual_address_space.map_extended(region.address, region.address.to_virtual_address_with_offset(higher_half_direct_map), region.size / x86_64.page_size, .{
                    .write = true,
                    .user = true,
                }, .no, true, higher_half_direct_map) catch unreachable;
            }
        }

        // Make sure we have mapped all the needed pages
        while (mapping_pages_mapped < x86_64.VAS.bootstrapping_physical_addresses.items.len) : (mapping_pages_mapped += 1) {
            const physical_address = x86_64.VAS.bootstrapping_physical_addresses.items[mapping_pages_mapped];
            std.log.scoped(.MappingPage).debug("Mapping 0x{x}", .{physical_address.value});
            const virtual_address = physical_address.to_virtual_address_with_offset(higher_half_direct_map);
            kernel.virtual_address_space.map_extended(physical_address, virtual_address, 1, .{ .write = true }, .no, true, higher_half_direct_map) catch unreachable;
        }

        kernel.virtual_address_space.make_current();
        kernel.virtual_address_space.copy_to_new(&kernel.virtual_address_space);
        kernel.higher_half_direct_map = VirtualAddress.new(higher_half_direct_map);

        // Update identity-mapped pointers to higher-half ones
        {
            var ptr = kernel.physical_address_space.usable.ptr;
            const len = kernel.physical_address_space.usable.len;
            _ = ptr;
            const ptrtoint = @ptrToInt(ptr);
            _ = ptrtoint;
            const final_address = ptrtoint + higher_half_direct_map;
            ptr = @intToPtr([*]PhysicalAddressSpace.MapEntry, final_address);
            kernel.physical_address_space.usable = ptr[0..len];
        }
        {
            var ptr = kernel.physical_address_space.reclaimable.ptr;
            const len = kernel.physical_address_space.reclaimable.len;
            const ptrtoint = @ptrToInt(ptr);
            _ = ptr;
            _ = len;
            const final_address = ptrtoint + higher_half_direct_map;
            ptr = @intToPtr([*]PhysicalAddressSpace.MapEntry, final_address);
            kernel.physical_address_space.reclaimable = ptr[0..len];
        }
        {
            var ptr = kernel.physical_address_space.framebuffer.ptr;
            const len = kernel.physical_address_space.framebuffer.len;
            const ptrtoint = @ptrToInt(ptr);
            const final_address = ptrtoint + higher_half_direct_map;
            ptr = @intToPtr([*]PhysicalMemoryRegion, final_address);
            kernel.physical_address_space.framebuffer = ptr[0..len];
        }
        {
            var ptr = kernel.physical_address_space.reserved.ptr;
            const len = kernel.physical_address_space.reserved.len;
            const ptrtoint = @ptrToInt(ptr);
            const final_address = ptrtoint + higher_half_direct_map;
            ptr = @intToPtr([*]PhysicalMemoryRegion, final_address);
            kernel.physical_address_space.reserved = ptr[0..len];
        }
        {
            var ptr = kernel.physical_address_space.kernel_and_modules.ptr;
            const len = kernel.physical_address_space.kernel_and_modules.len;
            const ptrtoint = @ptrToInt(ptr);
            const final_address = ptrtoint + higher_half_direct_map;
            ptr = @intToPtr([*]PhysicalMemoryRegion, final_address);
            kernel.physical_address_space.kernel_and_modules = ptr[0..len];
        }

        stivale_log.debug("Memory mapping initialized!", .{});

        {
            var reclaimable_consuming_timer = Timer.Scoped(.ConsumeReclaimable).start();
            defer reclaimable_consuming_timer.end_and_log();

            for (kernel.physical_address_space.reclaimable) |*region| {
                const bitset = region.get_bitset_extended(higher_half_direct_map);
                const bitset_size = bitset.len * @sizeOf(PhysicalAddressSpace.MapEntry.BitsetBaseType);
                region.allocated_size = std.align_forward(bitset_size, page_size);
                region.setup_bitset(higher_half_direct_map);
            }

            const old_reclaimable = kernel.physical_address_space.reclaimable.len;
            const now_usable_ptr = kernel.physical_address_space.usable.ptr;
            const now_usable_length = kernel.physical_address_space.usable.len;
            // @ZigBug This crashes the compiler. Can't find minimal repro
            //kernel.physical_address_space.usable.len += old_reclaimable;
            kernel.physical_address_space.usable = now_usable_ptr[0 .. now_usable_length + old_reclaimable];
            // Empty the reclaimable memory array since we have recovered everything
            // TODO: don't make reclaimable memory a member of physical address space if the memory is reclaimed here
            // Setting slice len here also crashes the compiler
            kernel.physical_address_space.reclaimable = &.{};

            //stivale_log.debug("Reclaimed reclaimable physical memory. Counting with {} more regions", .{old_reclaimable});
        }

        kernel.memory_initialized = true;

        {
            // Use the bootstrap allocator since we don't want any allocation happening here
            kernel.virtual_address_space.used_regions.ensureTotalCapacity(kernel.bootstrap_allocator.allocator(), 512) catch unreachable;
            kernel.virtual_address_space.free_regions.ensureTotalCapacity(kernel.bootstrap_allocator.allocator(), 512) catch unreachable;

            for (kernel.physical_address_space.usable) |*map_entry| {
                // Track all of it as linearly mapped for now
                const address = map_entry.descriptor.address;
                const total_page_count = @divExact(map_entry.descriptor.size, x86_64.page_size);
                const allocated_page_count = @divExact(map_entry.allocated_size, x86_64.page_size);
                const free_page_count = total_page_count - allocated_page_count;

                if (allocated_page_count != 0) {
                    const region = VirtualAddressSpace.Region{
                        .address = address.to_higher_half_virtual_address(),
                        .page_count = allocated_page_count,
                        .flags = VirtualAddressSpace.Flags{
                            .write = true,
                        },
                    };

                    std.log.scoped(.Track).debug("Tracked used region: (0x{x}, {})", .{ region.address.value, region.page_count });

                    kernel.virtual_address_space.add_used_region(region) catch unreachable;
                }

                if (free_page_count != 0) {
                    const region = VirtualAddressSpace.Region{
                        .address = address.to_higher_half_virtual_address().offset(allocated_page_count * x86_64.page_size),
                        .page_count = free_page_count,
                        .flags = VirtualAddressSpace.Flags{
                            .write = true,
                        },
                    };

                    std.log.scoped(.Track).debug("Tracked free region: (0x{x}, {})", .{ region.address.value, region.page_count });

                    kernel.virtual_address_space.add_free_region(region) catch unreachable;
                }
            }

            for (kernel.physical_address_space.framebuffer) |framebuffer_physical_region| {
                std.log.scoped(.Track).debug("Framebuffer physical region: (0x{x}, {})", .{ framebuffer_physical_region.address.value, framebuffer_physical_region.size });
                const physical_address = framebuffer_physical_region.address;
                const virtual_address = physical_address.to_higher_half_virtual_address();
                const page_count = @divExact(framebuffer_physical_region.size, x86_64.page_size);

                const region = VirtualAddressSpace.Region{
                    .address = virtual_address,
                    .page_count = page_count,
                    .flags = VirtualAddressSpace.Flags{
                        .write = true,
                    },
                };

                std.log.scoped(.Track).debug("Tracked framebuffer region: (0x{x}, {})", .{ region.address.value, region.page_count });

                kernel.virtual_address_space.add_used_region(region) catch unreachable;
            }

            for (kernel.physical_address_space.kernel_and_modules) |kernel_and_modules_physical_region| {
                std.log.scoped(.Track).debug("Kernel and modules physical region: (0x{x}, {})", .{ kernel_and_modules_physical_region.address.value, kernel_and_modules_physical_region.size });
                const physical_address = kernel_and_modules_physical_region.address;
                const virtual_address = physical_address.to_higher_half_virtual_address();
                const page_count = @divExact(kernel_and_modules_physical_region.size, x86_64.page_size);

                const region = VirtualAddressSpace.Region{
                    .address = virtual_address,
                    .page_count = page_count,
                    // TODO: rewrite flags
                    .flags = VirtualAddressSpace.Flags{},
                };

                std.log.scoped(.Track).debug("Tracked kernel and modules region: (0x{x}, {})", .{ region.address.value, region.page_count });

                kernel.virtual_address_space.add_used_region(region) catch unreachable;
            }

            // Lock down reserved region identity-mapped virtual addresses just in case
            for (kernel.physical_address_space.reserved) |reserved_physical_region| {
                std.log.scoped(.Track).debug("Reserved physical region: (0x{x}, {})", .{ reserved_physical_region.address.value, reserved_physical_region.size });

                const physical_address = reserved_physical_region.address;
                const virtual_address = VirtualAddress.new(physical_address.value);

                if (kernel.virtual_address_space.translate_address(virtual_address)) |mapped_physical_address| {
                    std.log.scoped(.Track).debug("Reserved identity virtual address 0x{x} is mapped to 0x{x}", .{ virtual_address.value, mapped_physical_address.value });
                    @panic("WTF");
                }

                const page_count = std.div_ceil(u64, reserved_physical_region.size, x86_64.page_size) catch unreachable;

                const region = VirtualAddressSpace.Region{
                    .address = virtual_address,
                    .page_count = page_count,
                    // TODO: rewrite flags
                    .flags = VirtualAddressSpace.Flags{},
                };

                std.log.scoped(.Track).debug("Tracked reserved region: (0x{x}, {})", .{ region.address.value, region.page_count });

                kernel.virtual_address_space.add_used_region(region) catch unreachable;
            }
        }

        // TODO: Handle virtual memory management later on
        stivale_log.debug("Paging initialized", .{});
    }

    // Compute again the struct
    stivale2_struct = stivale2_struct_physical_address.to_higher_half_virtual_address().access(*Struct);

    {
        const pmrs_struct = find(stivale.Struct.PMRs, stivale2_struct) orelse @panic("PMRs struct not found");
        const pmrs = pmrs_struct.pmrs()[0..pmrs_struct.entry_count];
        if (pmrs.len == 0) @panic("PMRs empty");

        std.assert(kernel.virtual_address_space.lock.status == 0);
        std.log.scoped(.EntryPoint).debug("PMR count: {}", .{pmrs.len});
        kernel.sections_in_memory = kernel.virtual_address_space.heap.allocator.alloc(VirtualMemoryRegion, pmrs.len) catch @panic("failed to allocate memory for PMRs");

        for (pmrs) |pmr, i| {
            const kernel_section = &kernel.sections_in_memory[i];
            kernel_section.address = VirtualAddress.new(pmr.address);
            kernel_section.size = pmr.size;
            //const permissions = pmr.permissions;
            //kernel_section.read = permissions & (1 << stivale.Struct.PMRs.PMR.readable) != 0;
            //kernel_section.write = permissions & (1 << stivale.Struct.PMRs.PMR.writable) != 0;
            //kernel_section.execute = permissions & (1 << stivale.Struct.PMRs.PMR.executable) != 0;
        }
        stivale_log.debug("Processed sections in memory", .{});
    }

    // This procedure copies the kernel file in a region which is usable and whose allocationcan be registered in the physical allocator bitset
    {
        const kernel_file_struct = find(stivale.Struct.KernelFileV2, stivale2_struct) orelse @panic("Kernel file struct not found");
        const file_address = PhysicalAddress.new(kernel_file_struct.kernel_file);
        const file_size = kernel_file_struct.kernel_size;
        // TODO: consider alignment?
        stivale_log.debug("allocation about to happen", .{});
        const dst = kernel.virtual_address_space.heap.allocator.alloc(u8, file_size) catch @panic("Unable to allocate memory for kernel file");
        stivale_log.debug("allocation did happen", .{});
        const src = file_address.to_higher_half_virtual_address().access([*]u8)[0..file_size];
        stivale_log.debug("Copying kernel file to (0x{x}, 0x{x})", .{ @ptrToInt(dst.ptr), @ptrToInt(dst.ptr) + dst.len });
        std.copy(u8, dst, src);
        kernel.file = FileInMemory{
            .address = VirtualAddress.new(@ptrToInt(dst.ptr)),
            .size = file_size,
        };
        stivale_log.debug("Processed kernel file in memory", .{});
    }

    {
        const stivale_framebuffer = find(stivale.Struct.Framebuffer, stivale2_struct) orelse @panic("Framebuffer struct not found");
        std.assert(stivale_framebuffer.framebuffer_pitch % stivale_framebuffer.framebuffer_width == 0);
        std.assert(stivale_framebuffer.framebuffer_bpp % @bitSizeOf(u8) == 0);
        const bytes_per_pixel = @intCast(u8, stivale_framebuffer.framebuffer_bpp / @bitSizeOf(u8));
        std.assert(stivale_framebuffer.framebuffer_pitch / stivale_framebuffer.framebuffer_width == bytes_per_pixel);
        kernel.bootloader_framebuffer = Framebuffer{
            .virtual_address = PhysicalAddress.new(stivale_framebuffer.framebuffer_addr).to_higher_half_virtual_address(),
            .width = stivale_framebuffer.framebuffer_width,
            .height = stivale_framebuffer.framebuffer_height,
            .bytes_per_pixel = bytes_per_pixel,
            .red_mask = .{ .size = stivale_framebuffer.red_mask_size, .shift = stivale_framebuffer.red_mask_shift },
            .blue_mask = .{ .size = stivale_framebuffer.blue_mask_size, .shift = stivale_framebuffer.blue_mask_shift },
            .green_mask = .{ .size = stivale_framebuffer.green_mask_size, .shift = stivale_framebuffer.green_mask_shift },
        };
        stivale_log.debug("Processed framebuffer", .{});
    }

    {
        cpu_initialization_context = CPUInitializationContext{
            .kernel_virtual_address_space = &kernel.virtual_address_space,
            .scheduler = &kernel.scheduler,
        };

        const smp_struct = find(stivale.Struct.SMP, stivale2_struct) orelse @panic("SMP struct not found");
        stivale_log.debug("SMP struct: {}", .{smp_struct});

        const cpu_count = smp_struct.cpu_count;
        const smps = smp_struct.smp_info()[0..cpu_count];
        std.assert(smps[0].lapic_id == smp_struct.bsp_lapic_id);
        // @Allocation
        bootstrap_context.cpu.idle_thread = &foo;
        bootstrap_context.cpu.idle_thread.context = &foo2;
        bootstrap_context.cpu.idle_thread.context = &foo2;
        bootstrap_context.cpu.idle_thread.address_space = &kernel.virtual_address_space;
        bootstrap_context.thread.context = &foo2;
        bootstrap_context.thread.address_space = &kernel.virtual_address_space;

        kernel.scheduler.lock.acquire();

        const threads = kernel.scheduler.thread_buffer.add_many(kernel.virtual_address_space.heap.allocator, cpu_count) catch @panic("wtf");
        kernel.scheduler.current_threads = kernel.virtual_address_space.heap.allocator.alloc(*Thread, threads.len) catch @panic("wtf");
        const thread_stack_size = Scheduler.default_kernel_stack_size;
        const thread_bulk_stack_allocation_size = threads.len * thread_stack_size;
        const thread_stacks = kernel.virtual_address_space.allocate(thread_bulk_stack_allocation_size, null, .{ .write = true }) catch @panic("wtF");
        kernel.scheduler.cpus = kernel.virtual_address_space.heap.allocator.alloc(CPU, cpu_count) catch @panic("wtF");
        kernel.scheduler.cpus[0].id = smps[0].processor_id;
        // Dummy context
        TLS.preset(&kernel.scheduler, &kernel.scheduler.cpus[0]);
        TLS.set_current(&kernel.scheduler, &threads[0], &kernel.scheduler.cpus[0]);
        // Map LAPIC address on just one CPU (since it's global)
        CPU.map_lapic();

        // TODO: ignore BSP cpu when AP initialization?
        for (threads) |*thread, thread_i| {
            kernel.scheduler.current_threads[thread_i] = thread;
            const cpu = &kernel.scheduler.cpus[thread_i];
            const smp = &smps[thread_i];

            const stack_allocation_offset = thread_i * thread_stack_size;
            const kernel_stack_address = thread_stacks.offset(stack_allocation_offset);
            const thread_stack = Scheduler.ThreadStack{
                .kernel = .{ .address = kernel_stack_address, .size = thread_stack_size },
                .user = .{ .address = kernel_stack_address, .size = thread_stack_size },
            };

            const entry_point = @ptrToInt(&kernel_smp_entry);
            kernel.scheduler.initialize_thread(thread, thread_i, &kernel.virtual_address_space, .kernel, .idle, entry_point, thread_stack);
            thread.cpu = cpu;
            cpu.idle_thread = thread;
            cpu.id = smp.processor_id;
            cpu.lapic.id = smp.lapic_id;
            const stack_pointer = thread.context.get_stack_pointer();
            smp.extra_argument = @ptrToInt(&cpu_initialization_context);
            smp.target_stack = stack_pointer;
            smp.goto_address = entry_point;
        }

        // TODO: TSS

        // Update bsp CPU
        // TODO: maybe this is necessary?

        kernel.scheduler.lock.release();

        stivale_log.debug("Processed SMP info", .{});
    }

    const current_thread = TLS.get_current();
    const cpu = current_thread.cpu orelse @panic("cpu");
    cpu.start(&kernel.scheduler, &kernel.virtual_address_space);

    _ = kernel.scheduler.spawn_kernel_thread(&kernel.virtual_address_space, .{
        .address = @ptrToInt(&main),
    });

    VAS.log_map_timer_register();

    entry_point_timer.end_and_log();
    cpu.ready = true;
    cpu.make_thread_idle();
}

/// Define root.log_level to override the default
pub const log_level: std.log.Level = switch (std.build_mode) {
    .Debug => .debug,
    .ReleaseSafe => .debug,
    .ReleaseFast, .ReleaseSmall => .info,
};

pub fn log(comptime level: std.log.Level, comptime scope: @TypeOf(.EnumLiteral), comptime format: []const u8, args: anytype) void {
    const scope_prefix = if (scope == .default) ": " else "(" ++ @tagName(scope) ++ "): ";
    const prefix = "[" ++ @tagName(level) ++ "] " ++ scope_prefix;
    default_logger.lock.acquire();
    defer default_logger.lock.release();
    const current_thread = TLS.get_current();
    if (current_thread.cpu) |current_cpu| {
        const processor_id = current_cpu.id;
        default_logger.writer.print("[Kernel] [Core #{}] [Thread #{}] ", .{ processor_id, current_thread.id }) catch unreachable;
    } else {
        default_logger.writer.print("[Kernel] [WARNING: unknown core] [Thread #{}] ", .{current_thread.id}) catch unreachable;
    }
    default_logger.writer.writeAll(prefix) catch unreachable;
    default_logger.writer.print(format, args) catch unreachable;
    default_logger.writer.writeByte('\n') catch unreachable;
}

pub fn panic(message: []const u8, _: ?*std.StackTrace) noreturn {
    crash.panic_extended("{s}", .{message}, @returnAddress(), @frameAddress());
}

const BootloaderInformation = struct {
    kernel_sections_in_memory: []VirtualMemoryRegion,
    kernel_file: FileInMemory,
    framebuffer: Framebuffer,
};

pub const BootstrapContext = struct {
    cpu: CPU,
    thread: Thread,
    context: Context,
};

fn find(comptime StructT: type, stivale2_struct: *Struct) ?*align(1) StructT {
    const offset = kernel.higher_half_direct_map.value;
    var tag_opt = @intToPtr(?*align(1) stivale.Tag, stivale2_struct.tags + offset);

    while (tag_opt) |tag| {
        if (tag.identifier == StructT.id) {
            return @ptrCast(*align(1) StructT, tag);
        }

        tag_opt = @intToPtr(?*align(1) stivale.Tag, tag.next + offset);
    }

    return null;
}

const CPUInitializationContext = struct {
    kernel_virtual_address_space: *VirtualAddressSpace,
    scheduler: *Scheduler,
};

var cpu_initialization_context: CPUInitializationContext = undefined;
var foo: Thread = undefined;
var foo2: Context = undefined;

export fn kernel_smp_entry(smp_info: *Struct.SMP.Info) callconv(.C) noreturn {
    const logger = std.log.scoped(.SMPEntry);
    const initialization_context = @intToPtr(*CPUInitializationContext, smp_info.extra_argument);
    const virtual_address_space = initialization_context.kernel_virtual_address_space;
    const scheduler = initialization_context.scheduler;
    const cpu_index = smp_info.processor_id;
    // Current thread is already set in the process_smp function
    TLS.preset(scheduler, &scheduler.cpus[cpu_index]);
    virtual_address_space.make_current();
    const current_thread = TLS.get_current();
    const cpu = current_thread.cpu orelse @panic("cpu");
    cpu.start(scheduler, virtual_address_space);
    logger.debug("CPU started", .{});

    while (!cpu.ready) {
        cpu.lapic.next_timer(10);
        asm volatile (
            \\sti
            \\pause
            \\hlt
        );
    }

    logger.debug("cpu is now ready", .{});
    cpu.make_thread_idle();
}

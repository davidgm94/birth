const common = @import("common");
const log = common.log.scoped(.Entry);
const kernel = @import("root");
const x86_64 = common.arch.x86_64;

const VirtualAddressSpace = common.VirtualAddressSpace;
pub export fn start(stivale2_struct_address: u64) noreturn {
    kernel.arch.x86_64.preinit_bsp();
    log.debug("Hello kernel!", .{});
    log.debug("Stivale2 address: 0x{x}", .{stivale2_struct_address});
    kernel.virtual_address_space = VirtualAddressSpace.bootstrapping() orelse unreachable;
    kernel.core_heap.init(&kernel.virtual_address_space);
    kernel.cpu_features = x86_64.enable_cpu_features();
    success_and_end();
    //const stivale2_struct_physical_address = PhysicalAddress.new(stivale2_struct_address);
    //kernel.higher_half_direct_map = Stivale2.process_higher_half_direct_map(stivale2_struct_physical_address.access_identity(*Stivale2.Struct)) catch unreachable;
    //const rsdp = Stivale2.process_rsdp(stivale2_struct_physical_address.access_identity(*Stivale2.Struct)) catch unreachable;
    //kernel.physical_address_space = Stivale2.process_memory_map(stivale2_struct_physical_address.access_identity(*Stivale2.Struct)) catch unreachable;
    //Paging.init(Stivale2.get_pmrs(stivale2_struct_physical_address.access_identity(*Stivale2.Struct)));
    //const region_type = kernel.physical_address_space.find_address(stivale2_struct_physical_address);
    //log.debug("Region type: {}", .{region_type});
    //Stivale2.process_bootloader_information(stivale2_struct_physical_address.access_higher_half(*Stivale2.Struct)) catch unreachable;
    //preinit_scheduler();
    //init_scheduler();
    //prepare_drivers(rsdp);
    //drivers_init(kernel.core_heap.allocator) catch |driver_init_error| kernel.crash("Failed to initialize drivers: {}", .{driver_init_error});
    //common.runtime_assert(@src(), Disk.drivers.items.len > 0);
    //common.runtime_assert(@src(), Filesystem.drivers.items.len > 0);
    //register_main_storage();
    //const file = kernel.main_storage.read_file_callback(Filesystem.drivers.items[0], "font.psf");
    //_ = file;
    //for (file[0..10]) |byte, i| {
    //log.debug("[{}] 0x{x}", .{ i, byte });
    //}

    //log.debug("File font.psf read successfully", .{});
    //log.debug("Everything OK", .{});

    //next_timer(1);
    //while (true) {
    //asm volatile (
    //\\cli
    //\\hlt
    //);
    //asm volatile ("pause" ::: "memory");
    //}
}

fn success_and_end() noreturn {
    log.debug("Everything OK", .{});
    common.arch.x86_64.spinloop_without_wasting_cpu();
}

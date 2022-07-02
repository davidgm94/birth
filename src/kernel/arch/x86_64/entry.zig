const common = @import("common");
const log = common.log.scoped(.Entry);
const kernel = @import("root");
const x86_64 = common.arch.x86_64;
const PhysicalAddress = common.PhysicalAddress;
const Stivale2 = x86_64.Stivale2;
const paging = x86_64.paging;

const VirtualAddressSpace = common.VirtualAddressSpace;
pub export fn start(stivale2_struct_address: u64) noreturn {
    kernel.arch.x86_64.preinit_bsp();
    log.debug("Hello kernel!", .{});
    log.debug("Stivale2 address: 0x{x}", .{stivale2_struct_address});
    kernel.core_heap.init(&kernel.bootstrapping_memory);
    kernel.cpu_features = x86_64.enable_cpu_features(kernel.arch.page_size);
    const stivale2_struct_physical_address = PhysicalAddress.new(stivale2_struct_address);
    const higher_half_direct_map = Stivale2.process_higher_half_direct_map(stivale2_struct_physical_address.access_kernel(*Stivale2.Struct)) catch @panic("Unable to get higher_half_direct_map");
    const rsdp = Stivale2.process_rsdp(stivale2_struct_physical_address.access_kernel(*Stivale2.Struct)) catch @panic("Unable to get RSDP");
    _ = rsdp;
    kernel.physical_address_space = Stivale2.process_memory_map(stivale2_struct_physical_address.access_kernel(*Stivale2.Struct), kernel.arch.page_size) catch unreachable;
    paging.init(&kernel.virtual_address_space, &kernel.physical_address_space, Stivale2.get_pmrs(stivale2_struct_physical_address.access_kernel(*Stivale2.Struct)), kernel.cpu_features, higher_half_direct_map);
    kernel.core_heap.virtual_address_space = &kernel.virtual_address_space;
    const bootloader_information = Stivale2.process_bootloader_information(kernel.core_heap.allocator, stivale2_struct_physical_address.access_kernel(*Stivale2.Struct), kernel.cpus[0]) catch unreachable;
    kernel.sections_in_memory = bootloader_information.kernel_sections_in_memory;
    kernel.file = bootloader_information.kernel_file;
    kernel.cpus = bootloader_information.cpus;
    const bsp = &kernel.cpus[0];
    x86_64.get_local_storage().?.cpu = bsp;
    x86_64.preinit_scheduler(&kernel.virtual_address_space, kernel.arch.x86_64.syscall_entry_point);
    x86_64.init_scheduler();
    x86_64.prepare_drivers(&kernel.virtual_address_space, rsdp);
    x86_64.drivers_init(&kernel.virtual_address_space, kernel.core_heap.allocator) catch |driver_init_error| kernel.crash("Failed to initialize drivers: {}", .{driver_init_error});
    common.runtime_assert(@src(), kernel.drivers.Disk.drivers.items.len > 0);
    common.runtime_assert(@src(), kernel.drivers.Filesystem.drivers.items.len > 0);
    x86_64.register_main_storage();
    const file = kernel.main_storage.read_file_callback(kernel.drivers.Filesystem.drivers.items[0], &kernel.virtual_address_space, "font.psf");
    for (file[0..10]) |byte, i| {
        log.debug("[{}] 0x{x}", .{ i, byte });
    }

    log.debug("File font.psf read successfully", .{});
    success_and_end();

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

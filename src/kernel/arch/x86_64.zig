const kernel = @import("root");
const common = @import("common");
const drivers = @import("../../drivers.zig");
const PCI = drivers.PCI;
const NVMe = drivers.NVMe;
const Virtio = drivers.Virtio;
const Disk = drivers.Disk;
const Filesystem = drivers.Filesystem;
const RNUFS = drivers.RNUFS;

const TODO = common.TODO;
const Allocator = common.Allocator;
const PhysicalAddress = common.PhysicalAddress;
const PhysicalAddressSpace = common.PhysicalAddressSpace;
const PhysicalMemoryRegion = common.PhysicalMemoryRegion;
const VirtualAddress = common.VirtualAddress;
const VirtualAddressSpace = common.VirtualAddressSpace;
const VirtualMemoryRegion = common.VirtualMemoryRegion;

const log = common.log.scoped(.x86_64);

pub const page_size = kernel.arch.check_page_size(0x1000);

var _zero: u64 = 0;
pub export fn start(stivale2_struct_address: u64) noreturn {
    _ = stivale2_struct_address;
    // We just need GS base to point to something so it doesn't crash
    //IA32_GS_BASE.write(@ptrToInt(&_zero));
    //log.debug("Hello kernel!", .{});
    //log.debug("Stivale2 address: 0x{x}", .{stivale2_struct_address});
    //kernel.virtual_address_space = VirtualAddressSpace.from_current() orelse unreachable;
    //kernel.core_heap.init(&kernel.virtual_address_space);
    //enable_cpu_features();
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

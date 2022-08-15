const std = @import("../../../common/std.zig");

const CPUID = @import("../../../common/arch/x86_64/cpuid.zig");
const crash = @import("../../crash.zig");
const drivers = @import("drivers.zig");
const kernel = @import("../../kernel.zig");
const log = std.log.scoped(.Entry);
const PhysicalAddress = @import("../../physical_address.zig");
const Stivale2 = @import("limine/stivale2/stivale2.zig");
const TLS = @import("tls.zig");
const VAS = @import("vas.zig");
const VirtualAddressSpace = @import("../../virtual_address_space.zig");
const x86_64 = @import("common.zig");

const panic = crash.panic;

var bootstrap_context: Stivale2.BootstrapContext = undefined;

pub fn function(stivale2_struct_address: u64) callconv(.C) noreturn {
    x86_64.max_physical_address_bit = CPUID.get_max_physical_address_bit();
    kernel.virtual_address_space = VirtualAddressSpace.bootstrapping();
    bootstrap_context.preinit_bsp(&kernel.scheduler, &kernel.virtual_address_space);
    log.debug("Hello kernel!", .{});
    log.debug("Stivale2 address: 0x{x}", .{stivale2_struct_address});
    const stivale2_struct_physical_address = PhysicalAddress.new(stivale2_struct_address);
    // This is just a cached version, not the global one (which is set after kernel address space initialization)
    const higher_half_direct_map = Stivale2.process_higher_half_direct_map(stivale2_struct_physical_address.access_kernel(*Stivale2.Struct)) catch @panic("Unable to get higher_half_direct_map");
    x86_64.rsdp_physical_address = Stivale2.process_rsdp(stivale2_struct_physical_address.access_kernel(*Stivale2.Struct)) catch @panic("Unable to get RSDP");
    kernel.physical_address_space = Stivale2.process_memory_map(stivale2_struct_physical_address.access_kernel(*Stivale2.Struct)) catch unreachable;
    VAS.init(&kernel.virtual_address_space, &kernel.physical_address_space, Stivale2.get_pmrs(stivale2_struct_physical_address.access_kernel(*Stivale2.Struct)), higher_half_direct_map);
    const bootloader_information = Stivale2.process_bootloader_information(&kernel.virtual_address_space, stivale2_struct_physical_address.access_kernel(*Stivale2.Struct), &bootstrap_context, &kernel.scheduler) catch unreachable;
    kernel.sections_in_memory = bootloader_information.kernel_sections_in_memory;
    kernel.file = bootloader_information.kernel_file;

    const current_thread = TLS.get_current();
    const cpu = current_thread.cpu orelse @panic("cpu");
    cpu.start(&kernel.virtual_address_space);

    kernel.device_manager.init(&kernel.virtual_address_space) catch |driver_init_error| panic("Failed to initialize drivers: {}", .{driver_init_error});
    std.assert(kernel.device_manager.disks.items.len > 0);
    std.assert(kernel.device_manager.filesystems.items.len > 0);

    asm volatile ("int $0x40");
    @panic("This is unreachable");
}

pub fn main() callconv(.C) noreturn {
    //_ = kernel.scheduler.load_executable(&kernel.virtual_address_space, .user, &kernel.physical_address_space, kernel.main_storage, "minimal.elf");
    asm volatile ("int $0x40");

    //success_and_end();

    //next_timer(1);
    while (true) {
        asm volatile (
            \\cli
            \\pause
            \\hlt
            ::: "memory");
    }
}

//fn success_and_end() noreturn {
//log.debug("Everything OK", .{});
//common.emulator.exit(.success);
//common.arch.x86_64.spinloop_without_wasting_cpu();
//}

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
pub const entry = @import("x86_64/entry.zig");

var bootstrap_cpu: common.arch.CPU = undefined;
var bootstrap_thread: common.Thread = undefined;

const x86_64 = common.arch.x86_64;
pub fn preinit_bsp() void {
    // @ZigBug: @ptrCast here crashes the compiler
    kernel.cpus = @intToPtr([*]common.arch.CPU, @ptrToInt(&bootstrap_cpu))[0..1];
    bootstrap_thread.local_storage.cpu = &bootstrap_cpu;
    x86_64.set_local_storage(&bootstrap_thread.local_storage);
    x86_64.IA32_GS_BASE.write(0);
}

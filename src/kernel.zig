const kernel = @This();

pub const arch = @import("kernel/arch.zig");
pub const Physical = @import("kernel/physical.zig");
pub const Virtual = @import("kernel/virtual.zig");
pub usingnamespace @import("kernel/assertion.zig");
pub usingnamespace @import("kernel/data_manipulation.zig");
const panic_file = @import("kernel/panic.zig");
pub const panic = panic_file.panic;
pub const TODO = panic_file.TODO;
pub const bounds = arch.Bounds;
pub const Spinlock = arch.Spinlock;
pub const AVL = @import("kernel/avl.zig");
pub const Heap = @import("kernel/heap.zig");
pub const CoreHeap = @import("kernel/core_heap.zig");
pub const PSF1 = @import("kernel/psf1.zig");
pub const scheduler = @import("kernel/scheduler.zig");
pub const ELF = @import("kernel/elf.zig");
pub const Syscall = @import("kernel/syscall.zig");
comptime {
    kernel.reference_all_declarations(Syscall);
}

pub var address_space = Virtual.AddressSpace.from_context(undefined);
pub var memory_region = Virtual.Memory.Region.new(Virtual.Address.new(0xFFFF900000000000), 0xFFFFF00000000000 - 0xFFFF900000000000);
pub const core_memory_region = Virtual.Memory.Region.new(Virtual.Address.new(0xFFFF800100000000), 0xFFFF800200000000 - 0xFFFF800100000000);

pub var core_heap: CoreHeap = undefined;
pub var font: PSF1.Font = undefined;
pub var higher_half_direct_map: Virtual.Address = undefined;
pub var file: File = undefined;
pub var sections_in_memory: []Virtual.Memory.RegionWithPermissions = undefined;

pub const File = struct {
    address: Virtual.Address,
    size: u64,
};

pub var cpus: []arch.CPU = undefined;

pub const PrivilegeLevel = enum(u1) {
    kernel = 0,
    user = 1,
};

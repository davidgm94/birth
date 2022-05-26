const std = @import("std");
const builtin = @import("builtin");

pub const log = std.log;
pub const current_arch = builtin.cpu.arch;
pub const build_mode = builtin.mode;
pub const arch = switch (current_arch) {
    .riscv64 => @import("arch/riscv64/riscv64.zig"),
    .x86_64 => @import("arch/x86_64.zig"),
    else => @compileError("CPU architecture not supported"),
};
pub const Memory = @import("memory.zig");
pub usingnamespace @import("assertion.zig");
pub usingnamespace @import("data_manipulation.zig");
pub usingnamespace @import("meta.zig");
const panic_file = @import("panic.zig");
pub const panic = panic_file.panic;
pub const TODO = panic_file.TODO;
pub const SourceLocation = panic_file.SourceLocation;
pub const bounds = arch.Bounds;
pub const Spinlock = arch.Spinlock;
pub const AVL = @import("avl.zig");
pub const Heap = @import("heap.zig");
pub const PSF1 = @import("psf1.zig");
pub const graphics = @import("graphics.zig");
pub const scheduler = @import("scheduler.zig");
pub const Filesystem = @import("filesystem.zig");
pub const Disk = @import("disk.zig");
// TODO: move this to drivers
pub const RNUFS = @import("rnu_fs.zig");
pub const driver = @import("driver.zig");
pub const Driver = driver.Driver;

pub var address_space: arch.Virtual.AddressSpace = undefined;
pub var heap: Heap = undefined;
pub var font: PSF1.Font = undefined;

pub const Writer = std.io.Writer;

const std = @import("std");
const builtin = @import("builtin");

pub const log = std.log;
pub const current_arch = builtin.cpu.arch;
pub const build_mode = builtin.mode;
pub const arch = @import("arch/riscv64/riscv64.zig");
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
pub const fs = @import("fs.zig");

pub var address_space: arch.Virtual.AddressSpace = undefined;
pub var heap: Heap = undefined;
pub var framebuffer: graphics.Framebuffer = undefined;
pub var font: PSF1.Font = undefined;
pub var framebuffer_initialized = false;

pub const Writer = std.io.Writer;

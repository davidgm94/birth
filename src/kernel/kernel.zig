const std = @import("std");
const builtin = @import("builtin");

pub const arch = @import("arch.zig");
pub const log = std.log;
pub const build_mode = builtin.mode;
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
pub const PhysicalMemory = @import("physical_memory.zig");
pub const ELF = @import("elf.zig");

pub var address_space: arch.Virtual.AddressSpace = undefined;
pub var heap: Heap = undefined;
pub var font: PSF1.Font = undefined;

pub const Writer = std.io.Writer;

pub var file_physical_address: u64 = 0;
pub var file_size: u64 = 0;
pub var file_memory_region: *Memory.Map.Entry = undefined;

pub var sections_in_memory: []Memory.Region.DescriptorWithPermissions = undefined;

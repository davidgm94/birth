const lib = @import("lib");
pub usingnamespace lib;

comptime {
    if (lib.os == .freestanding) @compileError("Host file included in non-host target");
}

const std = @import("std");
pub const ChildProcess = std.ChildProcess;

pub const posix = std.os;
pub const sync = std.os.sync;

const fs = std.fs;
pub const cwd = fs.cwd;
pub const Dir = fs.Dir;
pub const basename = fs.path.basename;
pub const dirname = fs.path.dirname;

const io = std.io;
pub const getStdOut = std.io.getStdOut;

const heap = std.heap;
pub const ArenaAllocator = heap.ArenaAllocator;
pub const page_allocator = heap.page_allocator;

pub const time = std.time;

pub const ArrayList = std.ArrayList;
pub const ArrayListAligned = std.ArrayListAligned;

// Build imports
pub const build = std.build;

pub fn allocateZeroMemory(bytes: u64) ![]align(0x1000) u8 {
    switch (lib.os) {
        .windows => {
            const windows = std.os.windows;
            return @ptrCast([*]align(0x1000) u8, @alignCast(0x1000, try windows.VirtualAlloc(null, bytes, windows.MEM_RESERVE | windows.MEM_COMMIT, windows.PAGE_READWRITE)))[0..bytes];
        },
        // Assume all systems are POSIX
        else => {
            const mmap = std.os.mmap;
            const PROT = std.os.PROT;
            const MAP = std.os.MAP;
            return try mmap(null, bytes, PROT.READ | PROT.WRITE, MAP.PRIVATE | MAP.ANONYMOUS, -1, 0);
        },
        .freestanding => @compileError("Not implemented yet"),
    }
}

pub const ExecutionError = error{failed};
pub fn spawnProcess(arguments: []const []const u8, allocator: lib.ZigAllocator) !void {
    var process = ChildProcess.init(arguments, allocator);
    const execution_result = try process.spawnAndWait();

    switch (execution_result) {
        .Exited => |exit_code| {
            switch (exit_code) {
                0 => {},
                else => return ExecutionError.failed,
            }
        },
        .Signal => |signal_code| {
            _ = signal_code;
            unreachable;
        },
        .Stopped, .Unknown => unreachable,
    }
}

pub fn diskImageFromZero(sector_count: usize, sector_size: u16) !lib.Disk.Image {
    const host = @import("host");
    const disk_bytes = try host.allocateZeroMemory(sector_count * sector_size);
    var disk_image = lib.Disk.Image{
        .disk = .{
            .type = .memory,
            .callbacks = .{
                .read = lib.Disk.Image.read,
                .write = lib.Disk.Image.write,
            },
            .disk_size = disk_bytes.len,
            .sector_size = sector_size,
        },
        .buffer_ptr = disk_bytes.ptr,
    };

    return disk_image;
}

pub fn diskImageFromFile(file_path: []const u8, sector_size: u16, allocator: lib.ZigAllocator) !lib.Disk.Image {
    const host = @import("host");
    const disk_memory = try host.cwd().readFileAlloc(allocator, file_path, lib.maxInt(usize));

    var disk_image = lib.Disk.Image{
        .disk = .{
            .type = .memory,
            .callbacks = .{
                .read = lib.Disk.Image.read,
                .write = lib.Disk.Image.write,
            },
            .disk_size = disk_memory.len,
            .sector_size = sector_size,
        },
        .buffer_ptr = disk_memory.ptr,
    };

    return disk_image;
}

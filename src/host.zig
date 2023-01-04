const common = @import("common.zig");
pub usingnamespace common;

comptime {
    if (common.os == .freestanding) @compileError("Host file included in non-host target");
}

const std = common.std;
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
    switch (common.os) {
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
pub fn spawnProcess(arguments: []const []const u8, allocator: common.Allocator) !void {
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

pub const ImageConfig = struct {
    image_name: []const u8,
    sector_count: u64,
    sector_size: u16,
    partition_table: common.PartitionTableType,
    partition: PartitionConfig,

    pub const default_path = "src/image_config.json";

    pub fn get(allocator: common.Allocator, path: []const u8) !ImageConfig {
        const image_config_file = cwd().readFileAlloc(allocator, path, common.maxInt(usize)) catch unreachable;
        var json_stream = common.json.TokenStream.init(image_config_file);
        return try common.json.parse(ImageConfig, &json_stream, .{ .allocator = allocator });
    }
};

pub const PartitionConfig = struct {
    name: []const u8,
    filesystem: common.FilesystemType,
    first_lba: u64,
};

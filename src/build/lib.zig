const std = @import("std");
const builtin = @import("builtin");

comptime {
    if (os == .freestanding) @compileError("This is only meant to be imported in build.zig");
}

pub const Builder = std.build.Builder;
pub const LibExeObjStep = std.build.LibExeObjStep;
pub const Step = std.build.Step;
pub const RunStep = std.build.RunStep;
pub const FileSource = std.build.FileSource;
pub const OptionsStep = std.build.OptionsStep;
pub const WriteFileStep = std.build.WriteFileStep;

pub const Target = std.Target;
pub const Arch = Target.Cpu.Arch;
pub const CrossTarget = std.zig.CrossTarget;

pub const os = builtin.target.os.tag;
pub const arch = builtin.target.cpu.arch;

pub const concatenate = std.mem.concat;
pub const memory_equal = std.mem.eql;
pub const memory_copy = std.mem.copy;
pub const memory_set = std.mem.set;
pub const maxInt = std.math.maxInt;

pub const ArrayList = std.ArrayList;
pub const ArrayListAlignedUnmanaged = std.ArrayListAlignedUnmanaged;
pub const Allocator = std.mem.Allocator;

pub const assert = std.debug.assert;
pub const print = std.debug.print;
pub const log = std.log;

pub const fork = std.os.fork;
pub const ChildProcess = std.ChildProcess;
pub const waitpid = std.os.waitpid;

pub fn allocate_zero_memory(bytes: u64) ![]align(0x1000) u8 {
    switch (os) {
        .windows => {
            const windows = std.os.windows;
            return @ptrCast([*]align(0x1000) u8, try windows.VirtualAlloc(null, bytes, windows.MEM_RESERVE | windows.MEM_COMMIT, windows.PAGE_READWRITE))[0..bytes];
        },
        else => {
            const mmap = std.os.mmap;
            const PROT = std.os.PROT;
            const MAP = std.os.MAP;
            return try mmap(null, bytes, PROT.READ | PROT.WRITE, MAP.PRIVATE | MAP.ANONYMOUS, -1, 0);
        },
    }
}

pub const cwd = std.fs.cwd;
pub const Dir = std.fs.Dir;
pub const path = std.fs.path;

pub const QEMU = @import("../common/qemu/common.zig");

pub fn add_qemu_debug_isa_exit(builder: *Builder, list: *ArrayList([]const u8), qemu_debug_isa_exit: QEMU.ISADebugExit) !void {
    try list.append("-device");
    try list.append(builder.fmt("isa-debug-exit,iobase=0x{x},iosize=0x{x}", .{ qemu_debug_isa_exit.port, qemu_debug_isa_exit.size }));
}

const DiskInterface = @import("../drivers/disk_interface.zig");
const DMA = @import("../drivers/dma.zig");

pub const Disk = struct {
    const BufferType = ArrayListAlignedUnmanaged(u8, 0x1000);

    disk: DiskInterface,
    buffer: BufferType,

    fn access(disk: *DiskInterface, buffer: *DMA.Buffer, disk_work: DiskInterface.Work, extra_context: ?*anyopaque) u64 {
        const build_disk = @fieldParentPtr(Disk, "disk", disk);
        _ = extra_context;
        const sector_size = disk.sector_size;
        log.debug("Disk work: {}", .{disk_work});
        switch (disk_work.operation) {
            .write => {
                const work_byte_size = disk_work.sector_count * sector_size;
                const byte_count = work_byte_size;
                const write_source_buffer = @intToPtr([*]const u8, buffer.virtual_address)[0..byte_count];
                const disk_slice_start = disk_work.sector_offset * sector_size;
                log.debug("Disk slice start: {}. Disk len: {}", .{ disk_slice_start, build_disk.buffer.items.len });
                assert(disk_slice_start == build_disk.buffer.items.len);
                build_disk.buffer.appendSliceAssumeCapacity(write_source_buffer);

                return byte_count;
            },
            .read => {
                const offset = disk_work.sector_offset * sector_size;
                const bytes = disk_work.sector_count * sector_size;
                const previous_len = build_disk.buffer.items.len;

                if (offset >= previous_len or offset + bytes > previous_len) build_disk.buffer.items.len = build_disk.buffer.capacity;
                memory_copy(u8, @intToPtr([*]u8, buffer.virtual_address)[0..bytes], build_disk.buffer.items[offset .. offset + bytes]);
                if (offset >= previous_len or offset + bytes > previous_len) build_disk.buffer.items.len = previous_len;

                return disk_work.sector_count;
            },
        }
    }

    fn get_dma_buffer(disk: *DiskInterface, allocator: Allocator, sector_count: u64) Allocator.Error!DMA.Buffer {
        const allocation_size = disk.sector_size * sector_count;
        const alignment = 0x1000;
        log.debug("DMA buffer allocation size: {}, alignment: {}", .{ allocation_size, alignment });
        const allocation_slice = try allocator.allocBytes(@intCast(u29, alignment), allocation_size, 0, 0);
        memory_set(u8, allocation_slice, 0);
        log.debug("Allocation address: 0x{x}", .{@ptrToInt(allocation_slice.ptr)});
        return DMA.Buffer.new(allocator, .{ .size = allocation_size, .alignment = alignment });
    }

    pub fn new(buffer: BufferType) Disk {
        return Disk{
            .disk = DiskInterface{
                .sector_size = 0x200,
                .access = access,
                .get_dma_buffer = get_dma_buffer,
                .type = .memory,
            },
            .buffer = buffer,
        };
    }
};

const RNUFS = @This();

const std = @import("../../common/std.zig");

const crash = @import("../../kernel/crash.zig");
const DeviceManager = @import("../../kernel/device_manager.zig");
const Disk = @import("../disk.zig");
const DMA = @import("../dma.zig");
const Drivers = @import("../common.zig");
const Filesystem = @import("../filesystem.zig");
const FilesystemInterface = @import("../filesystem_interface.zig");
const common = @import("../../common/rnufs.zig");
const VirtualAddressSpace = @import("../../kernel/virtual_address_space.zig");

const log = std.log.scoped(.RNUFS);
const Allocator = std.Allocator;
const panic = crash.panic;

fs: Filesystem,

const InitError = error{
    not_found,
};

// TODO: free
pub fn init(device_manager: *DeviceManager, virtual_address_space: *VirtualAddressSpace, disk: *Disk, comptime maybe_driver_tree: ?[]const Drivers.Tree) !void {
    var dma_buffer = try disk.interface.get_dma_buffer(&disk.interface, virtual_address_space.heap.allocator, 1);
    const result = disk.interface.access(&disk.interface, &dma_buffer, .{
        .sector_offset = 0,
        .sector_count = 1,
        .operation = .read,
    }, virtual_address_space);
    std.assert(result == 1);
    std.assert(dma_buffer.completed_size == disk.interface.sector_size);

    const possible_signature = @intToPtr([*]const u8, dma_buffer.address)[0..common.default_signature.len];
    if (!std.string_eq(possible_signature, &common.default_signature)) {
        return InitError.not_found;
    }

    const rnufs = try virtual_address_space.heap.allocator.create(RNUFS);
    rnufs.fs = .{
        .interface = .{
            .type = .RNU,
            .disk = &disk.interface,
            .callback_read_file = read_file,
            .callback_write_file = common.write_file,
        },
    };
    if (maybe_driver_tree) |driver_tree| {
        inline for (driver_tree) |driver_node| {
            try driver_node.type.init(device_manager, virtual_address_space, &rnufs.fs, driver_node.children);
        }
    }
}

pub fn seek_file(fs_driver: *FilesystemInterface, allocator: Allocator, name: []const u8, extra_context: ?*anyopaque) ?SeekResult {
    const virtual_address_space = @ptrCast(*VirtualAddressSpace, @alignCast(@alignOf(VirtualAddressSpace), extra_context));
    log.debug("Seeking file {s}", .{name});
    const sectors_to_read_at_time = 1;
    const sector_size = fs_driver.disk.sector_size;
    var sector: u64 = std.bytes_to_sector(@sizeOf(common.Superblock), sector_size, .must_be_exact);
    var search_buffer = fs_driver.disk.get_dma_buffer(fs_driver.disk, allocator, sectors_to_read_at_time) catch {
        log.err("Unable to allocate search buffer", .{});
        return null;
    };

    while (true) {
        defer search_buffer.completed_size = 0;

        log.debug("FS driver asking read", .{});
        const sectors_read = fs_driver.disk.access(fs_driver.disk, &search_buffer, Disk.Work{
            .sector_offset = sector,
            .sector_count = sectors_to_read_at_time,
            .operation = .read,
        }, virtual_address_space);
        log.debug("FS driver ending read", .{});
        if (sectors_read != sectors_to_read_at_time) panic("Driver internal error: cannot seek file", .{});
        //for (search_buffer.address.access([*]const u8)[0..sector_size]) |byte, i| {
        //if (byte != 0) log.debug("[{}] 0x{x}", .{ i, byte });
        //}
        var node = @intToPtr(*common.Node, search_buffer.address);
        if (node.type == .empty) break;
        const node_name_cstr = @ptrCast([*:0]const u8, &node.name);
        const node_name = node_name_cstr[0..std.cstr_len(node_name_cstr)];
        if (node_name.len == 0) break;

        if (name[0] == 0x00) @panic("Wtf");

        log.debug("Wanted node name: (\"{s}\", {}) (First byte = 0x{x}). This node name: (\"{s}\", {})", .{ name, name.len, name[0], node_name, node_name.len });

        if (std.string_eq(node_name, name)) {
            return SeekResult{
                .sector = sector,
                .node = node.*,
            };
        }

        log.debug("Names don't match", .{});

        const sectors_to_add = 1 + std.bytes_to_sector(node.size, sector_size, .can_be_not_exact);
        log.debug("Sectors to add: {}", .{sectors_to_add});
        sector += sectors_to_add;
    }

    @panic("not found");
}

pub fn read_file(fs_driver: *FilesystemInterface, allocator: Allocator, name: []const u8, extra_context: ?*anyopaque) Filesystem.ReadError![]const u8 {
    const virtual_address_space = @ptrCast(*VirtualAddressSpace, @alignCast(@alignOf(VirtualAddressSpace), extra_context));
    log.debug("About to read file {s}...", .{name});
    if (seek_file(fs_driver, allocator, name, extra_context)) |seek_result| {
        const sector_size = fs_driver.disk.sector_size;
        const node_size = seek_result.node.size;
        log.debug("File size: {}", .{node_size});
        const sector_count = std.bytes_to_sector(node_size, sector_size, .can_be_not_exact);
        var buffer = fs_driver.disk.get_dma_buffer(fs_driver.disk, allocator, sector_count) catch {
            @panic("Unable to allocate read buffer");
        };
        const sector_offset = seek_result.sector + 1;
        log.debug("Sector offset: {}. Sector count: {}", .{ sector_offset, sector_count });
        // Add one to skip the metadata
        const sectors_read = fs_driver.disk.access(fs_driver.disk, &buffer, Disk.Work{
            .sector_offset = sector_offset,
            .sector_count = sector_count,
            .operation = .read,
        }, virtual_address_space);

        if (sectors_read != sector_count) panic("Driver internal error: cannot read file", .{});

        return @intToPtr([*]const u8, buffer.address)[0..node_size];
    } else {
        @panic("unable to find file");
    }
}

pub const SeekResult = struct {
    sector: u64,
    node: common.Node,
};

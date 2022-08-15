const RNUFS = @This();

const std = @import("../../common/std.zig");

const crash = @import("../../kernel/crash.zig");
const DeviceManager = @import("../../kernel/device_manager.zig");
const Disk = @import("../disk.zig");
const DMA = @import("../dma.zig");
const Drivers = @import("../common.zig");
const Filesystem = @import("../filesystem.zig");
const common = @import("../../common/rnufs.zig");
const VirtualAddressSpace = @import("../../kernel/virtual_address_space.zig");

const log = std.log.scoped(.RNUFS);
const Allocator = std.Allocator;
const panic = crash.panic;

fs: Filesystem,

// TODO: free
pub fn init(device_manager: *DeviceManager, virtual_address_space: *VirtualAddressSpace, disk: *Disk, comptime maybe_driver_tree: ?[]const Drivers.Tree) !void {
    var dma_buffer = try disk.interface.get_dma_buffer(&disk.interface, virtual_address_space.heap.allocator, 1);
    const result = disk.interface.access(&disk.interface, &dma_buffer, .{
        .sector_offset = 0,
        .sector_count = 1,
        .operation = .read,
    }, virtual_address_space);
    std.assert(result == 1);
    const rnufs = try virtual_address_space.heap.allocator.create(RNUFS);
    if (maybe_driver_tree) |driver_tree| {
        inline for (driver_tree) |driver_node| {
            try driver_node.type.init(device_manager, virtual_address_space, &rnufs.fs, driver_node.children);
        }
    }
}

pub fn seek_file(fs_driver: *Filesystem, allocator: Allocator, special_context: u64, name: []const u8) ?SeekResult {
    const virtual_address_space = @intToPtr(*VirtualAddressSpace, special_context);
    log.debug("Seeking file {s}", .{name});
    const sectors_to_read_at_time = 1;
    const sector_size = fs_driver.disk.sector_size;
    var sector: u64 = std.bytes_to_sector(@sizeOf(common.Superblock), sector_size, .must_be_exact);
    var search_buffer = fs_driver.disk.get_dma_buffer(fs_driver.disk, allocator, sectors_to_read_at_time) catch {
        log.err("Unable to allocate search buffer", .{});
        return null;
    };

    while (true) {
        log.debug("FS driver asking read", .{});
        const sectors_read = fs_driver.disk.access(fs_driver.disk, @ptrToInt(virtual_address_space), &search_buffer, Disk.Work{
            .sector_offset = sector,
            .sector_count = sectors_to_read_at_time,
            .operation = .read,
        });
        log.debug("FS driver ending read", .{});
        if (sectors_read != sectors_to_read_at_time) panic("Driver internal error: cannot seek file", .{});
        //for (search_buffer.address.access([*]const u8)[0..sector_size]) |byte, i| {
        //if (byte != 0) log.debug("[{}] 0x{x}", .{ i, byte });
        //}
        var node = search_buffer.address.access(*common.Node);
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

pub fn read_file(fs_driver: *Filesystem, allocator: Allocator, special_context: u64, name: []const u8) []const u8 {
    const virtual_address_space = @intToPtr(*VirtualAddressSpace, special_context);
    log.debug("About to read file {s}...", .{name});
    if (seek_file(fs_driver, allocator, special_context, name)) |seek_result| {
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
        const sectors_read = fs_driver.disk.access(fs_driver.disk, @ptrToInt(virtual_address_space), &buffer, Disk.Work{
            .sector_offset = sector_offset,
            .sector_count = sector_count,
            .operation = .read,
        });

        if (sectors_read != sector_count) panic(@src(), "Driver internal error: cannot read file", .{});

        return buffer.address.access([*]const u8)[0..node_size];
    } else {
        @panic("unable to find file");
    }
}

pub const SeekResult = struct {
    sector: u64,
    node: common.Node,
};

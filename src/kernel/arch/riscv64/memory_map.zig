const kernel = @import("../../kernel.zig");
const Physical = kernel.arch.Physical;
const TODO = kernel.TODO;

var available: BootloaderMemoryRegionGroup = undefined;
var reserved: BootloaderMemoryRegionGroup = undefined;

pub const BootloaderMemoryRegionGroup = struct {
    array: [64]RegionDescriptor,
    count: u64,
};

const RegionDescriptor = kernel.arch.Physical.Region.Descriptor;

pub const MemoryMap = struct {
    available: []RegionDescriptor,
    reserved: []RegionDescriptor,
};

pub fn get() MemoryMap {
    const memory_properties = kernel.arch.device_tree.find_property("memory", null, "reg", .start) orelse @panic("not found");
    var bytes_processed: u64 = 0;

    var memory_map: MemoryMap = undefined;
    memory_map.available.ptr = &available.array;
    memory_map.available.len = 0;
    memory_map.reserved.ptr = &reserved.array;
    memory_map.reserved.len = 0;

    while (bytes_processed < memory_properties.value.len) {
        memory_map.available.len += 1;
        var region = &memory_map.available[memory_map.available.len - 1];
        region.address = kernel.arch.dt_read_int(u64, memory_properties.value[bytes_processed..]);
        bytes_processed += @sizeOf(u64);
        const region_size = kernel.arch.dt_read_int(u64, memory_properties.value[bytes_processed..]);
        kernel.assert(@src(), region_size % kernel.arch.page_size == 0);
        region.page_count = region_size / kernel.arch.page_size;
        bytes_processed += @sizeOf(u64);
    }

    if (kernel.arch.device_tree.find_node("reserved-memory", .exact)) |find_result| {
        var parser = find_result.parser;
        while (parser.get_subnode()) |subnode_name| {
            kernel.arch.early_print("Getting subnode: {s}\n", .{subnode_name});

            if (parser.find_property_in_current_node("reg")) |reserved_memory_prop| {
                bytes_processed = 0;

                while (bytes_processed < reserved_memory_prop.value.len) {
                    memory_map.reserved.len += 1;
                    var region = &memory_map.reserved[memory_map.reserved.len - 1];
                    region.address = kernel.arch.dt_read_int(u64, reserved_memory_prop.value[bytes_processed..]);
                    bytes_processed += @sizeOf(u64);
                    const region_size = kernel.arch.dt_read_int(u64, reserved_memory_prop.value[bytes_processed..]);
                    kernel.assert(@src(), region_size % kernel.arch.page_size == 0);
                    region.page_count = region_size / kernel.arch.page_size;
                    bytes_processed += @sizeOf(u64);
                }
            }
        }
    }

    kernel.arch.early_write("Regions:\n");
    for (memory_map.available) |region, i| {
        kernel.arch.early_print("[{}] (0x{x}, {})\n", .{ i, region.address, region.page_count });
    }

    kernel.arch.early_write("Reserved regions:\n");
    for (memory_map.reserved) |region, i| {
        kernel.arch.early_print("[{}] (0x{x}, {})\n", .{ i, region.address, region.page_count });
    }

    return memory_map;
}
const kernel = @import("../../kernel.zig");
const print = kernel.arch.early_print;
const write = kernel.arch.early_write;
const TODO = kernel.TODO;

const MemoryMap = @import("memory_map.zig");
var bitset_memory: [0x400_000 + (10 * kernel.arch.page_size)]u8 align(kernel.arch.page_size) = undefined;
var bitset_byte_count: u64 = 0;

var available_regions: []Region = undefined;
var reserved_regions: []Region.Descriptor = undefined;
var _reserved: [64]Region.Descriptor = undefined;
var _available: [64]Region = undefined;

pub var kernel_region: *Region.Descriptor = undefined;
pub var device_tree_region: *Region.Descriptor = undefined;

pub const Region = struct {
    descriptor: Region.Descriptor,
    allocated_page_count: u64,
    bitset: []u64,

    pub const Descriptor = struct {
        address: u64,
        page_count: u64,
    };
};

pub fn init() void {
    const memory_map = MemoryMap.get();
    reserved_regions.ptr = &_reserved;
    reserved_regions.len = memory_map.reserved.len;
    kernel.copy(Region.Descriptor, reserved_regions, memory_map.reserved);

    const kernel_start = kernel.bounds.get_start();
    const kernel_end = kernel.bounds.get_end();
    const kernel_size = kernel_end - kernel_start;
    reserved_regions.len += 1;
    kernel_region = &reserved_regions[reserved_regions.len - 1];
    kernel_region.address = kernel_start;
    kernel_region.page_count = kernel_size / kernel.arch.page_size;
    kernel.assert(@src(), kernel_size & (kernel.arch.page_size - 1) == 0);

    reserved_regions.len += 1;
    device_tree_region = &reserved_regions[reserved_regions.len - 1];
    device_tree_region.address = kernel.arch.device_tree.base_address;
    device_tree_region.page_count = kernel.align_forward(kernel.arch.device_tree.header.size, kernel.arch.page_size) / kernel.arch.page_size;

    write("Reserved regions\n");
    for (reserved_regions) |reserved, i| {
        print("[{}] (0x{x}, {})\n", .{ i, reserved.address, reserved.page_count });
    }

    available_regions.ptr = &_available;
    available_regions.len = memory_map.available.len;
    for (memory_map.available) |available, i| {
        available_regions[i].descriptor = available;
    }

    for (reserved_regions) |reserved| {
        const reserved_size = reserved.page_count * kernel.arch.page_size;
        for (available_regions) |*available, available_i| {
            const available_size = available.descriptor.page_count * kernel.arch.page_size;
            if (reserved.address >= available.descriptor.address and reserved.address < available.descriptor.address + available_size) {
                const start_matches = reserved.address == available.descriptor.address;
                const end_matches = reserved.address + reserved_size == available.descriptor.address + available_size;

                if (!start_matches and !end_matches) {
                    kernel.assert(@src(), available_i == available_regions.len - 1);
                    const first = available;
                    available_regions.len += 1;
                    const second = &available_regions[available_i + 1];
                    const original_size = available_size;
                    second.descriptor.address = reserved.address + reserved_size;
                    const original_end_address = first.descriptor.address + original_size;
                    second.descriptor.page_count = (original_end_address - second.descriptor.address) / kernel.arch.page_size;
                    first.descriptor.page_count -= second.descriptor.page_count + reserved.page_count;
                } else if (start_matches and end_matches) {
                    kernel.assert(@src(), available_i == available_regions.len - 1);
                    available_regions.len -= 1;
                } else if (start_matches) {
                    available.descriptor.address = reserved.address + reserved_size;
                    available.descriptor.page_count -= reserved.page_count;
                } else if (end_matches) {
                    TODO(@src());
                } else {
                    @panic("unreachableeEEEEE");
                }

                break;
            }
            // TODO: contemplate the case in which the reserved region is bigger than the available region
        }
    }

    write("Available regions:\n");
    for (available_regions) |region, i| {
        print("[{}] (0x{x}, {} -- 0x{x})\n", .{ i, region.descriptor.address, region.descriptor.page_count, region.descriptor.page_count * kernel.arch.page_size });
    }

    for (available_regions) |*region| {
        // Align to u64
        const bytes_to_allocate = kernel.align_forward(@sizeOf(u64), (region.descriptor.page_count / @bitSizeOf(u8)) + @boolToInt(region.descriptor.page_count % @bitSizeOf(u8) != 0));
        bitset_byte_count = kernel.align_forward(bitset_byte_count, kernel.arch.page_size);
        region.bitset.ptr = @ptrCast([*]u64, @alignCast(kernel.arch.page_size, &bitset_memory[bitset_byte_count]));
        region.bitset.len = bytes_to_allocate / @sizeOf(u64);
        bitset_byte_count += bytes_to_allocate;
    }
}

fn allocate(page_count: u64, zero: bool) ?u64 {
    const take_hint = true;
    var first_address: u64 = 0;

    // TODO: don't allocate if they are different regions (this can cause issues?)
    for (available_regions) |*region| {
        if (region.descriptor.page_count - region.allocated_page_count >= page_count) {
            var region_allocated_page_count: u64 = 0;

            if (take_hint) {
                const hint_index = region.allocated_page_count / @bitSizeOf(u64);
                print("Hint index: {}\n", .{hint_index});

                for (region.bitset[hint_index..]) |*bitset_elem, byte_i| {
                    comptime var bit: u64 = 0;
                    inline while (bit < @bitSizeOf(u64)) : (bit += 1) {
                        const bit_set = bitset_elem.* & (1 << bit) != 0;
                        print("[B{}][b{}] = {}\n", .{ hint_index + byte_i, bit, bit_set });
                        if (region_allocated_page_count == page_count) {
                            region.allocated_page_count += region_allocated_page_count;
                            kernel.assert(@src(), first_address != 0);
                            if (zero) {
                                kernel.zero(@intToPtr([*]u8, first_address)[0..page_count * kernel.arch.page_size]);
                            }
                            return first_address;
                        } else {
                            if (!bit_set) {
                                if (first_address == 0) {
                                    const offset = (bit + (hint_index * @bitSizeOf(u64))) * kernel.arch.page_size;
                                    first_address = region.descriptor.address + offset;
                                }

                                bitset_elem.* = bitset_elem.* | (1 << bit);
                                region_allocated_page_count += 1;
                            }
                        }
                    }
                }
            } else {
                TODO(@src());
            }

            @panic("deallocate and move to another region");
        }
    }

    @panic("allocation failed, no memory");
}

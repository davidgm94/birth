const kernel = @import("kernel.zig");
const log = kernel.log.scoped(.PhysicalMemory);
const TODO = kernel.TODO;
pub var map: kernel.Memory.Map = undefined;
pub fn init() void {
    map = kernel.arch.get_memory_map();
    map.debug();
}

pub fn allocate_assuming_identity_mapping(comptime T: type) ?*T {
    const page_count = kernel.bytes_to_pages(@sizeOf(T), false);
    return @intToPtr(*T, allocate_pages(page_count) orelse return null);
}

pub fn allocate_pages(page_count: u64) ?u64 {
    const take_hint = true;
    const size = page_count * kernel.arch.page_size;
    // TODO: don't allocate if they are different regions (this can cause issues?)
    for (map.usable) |*region| {
        if (region.descriptor.size - region.allocated_size >= size) {
            const region_page_count = region.descriptor.size / kernel.arch.page_size;
            const supposed_bitset_size = region_page_count / @bitSizeOf(kernel.Memory.Map.Entry.BitsetBaseType);
            const bitset = region.get_bitset();
            kernel.assert(@src(), bitset.len >= supposed_bitset_size);
            var region_allocated_page_count: u64 = 0;
            const allocated_page_count = region.allocated_size / kernel.arch.page_size;

            const start_index = if (take_hint) allocated_page_count / @bitSizeOf(u64) else 0;
            var first_address: u64 = 0;

            bitset_loop: for (bitset[start_index..]) |*bitset_elem| {
                comptime var bit: u64 = 0;

                inline while (bit < @bitSizeOf(u64)) : (bit += 1) {
                    const bit_set = bitset_elem.* & (1 << bit) != 0;
                    if (region_allocated_page_count == page_count) {
                        break :bitset_loop;
                    } else {
                        if (!bit_set) {
                            if (first_address == 0) {
                                const offset = (bit + (start_index * @bitSizeOf(u64))) * kernel.arch.page_size;
                                first_address = region.descriptor.address + offset;
                            }

                            bitset_elem.* = bitset_elem.* | (1 << bit);
                            region_allocated_page_count += 1;
                        }
                    }
                }
            }

            if (region_allocated_page_count == page_count) {
                const result = first_address;
                region.allocated_size += region_allocated_page_count * kernel.arch.page_size;
                kernel.assert(@src(), result != 0);
                return result;
            }

            kernel.assert(@src(), region.allocated_size + size > region.descriptor.size);
            kernel.assert(@src(), first_address != 0);
            const original_allocated_size = region.allocated_size - (region_allocated_page_count * kernel.arch.page_size);
            const original_allocated_page_count = original_allocated_size / kernel.arch.page_size;
            var byte = original_allocated_page_count / @bitSizeOf(u64);
            var bit = original_allocated_page_count % @bitSizeOf(u64);

            kernel.assert(@src(), region_allocated_page_count > 0);

            if (bit > 0) {
                while (bit < @bitSizeOf(u64)) : (bit += 1) {
                    bitset[byte] &= (~(@as(u64, 1) << @intCast(u6, bit)));
                    region_allocated_page_count -= 1;
                }
            }

            if (region_allocated_page_count >= 64) {
                TODO(@src());
            }

            if (region_allocated_page_count > 0) {
                TODO(@src());
            }

            region.allocated_size = original_allocated_size;
        }
    }

    @panic("allocation failed, no memory");
}

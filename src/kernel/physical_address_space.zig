const PhysicalAddressSpace = @This();

const std = @import("../common/std.zig");

const arch = @import("arch/common.zig");
const crash = @import("crash.zig");
const kernel = @import("kernel.zig");
const PhysicalAddress = @import("physical_address.zig");
const PhysicalMemoryRegion = @import("physical_memory_region.zig");
const Spinlock = @import("spinlock.zig");

const log = std.log.scoped(.PhysicalAddressSpace);
const TODO = crash.TODO;
const page_size = arch.page_size;

usable: []MapEntry = &.{},
reclaimable: []MapEntry = &.{},
framebuffer: []PhysicalMemoryRegion = &.{},
kernel_and_modules: []PhysicalMemoryRegion = &.{},
reserved: []PhysicalMemoryRegion = &.{},
lock: Spinlock = .{},

pub fn allocate(physical_address_space: *PhysicalAddressSpace, page_count: u64) ?PhysicalAddress {
    physical_address_space.lock.acquire();
    defer physical_address_space.lock.release();
    const take_hint = true;
    const size = page_count * page_size;
    // TODO: don't allocate if they are different regions (this can cause issues?)
    //log.debug("Debugging", .{});
    //const slice = @ptrCast([*]u64, physical_address_space)[0 .. @sizeOf(PhysicalAddressSpace) / @sizeOf(u64)];
    //for (slice) |int, int_i| {
    //log.debug("[{}] = 0x{x}", .{ int_i, int });
    //}
    for (physical_address_space.usable) |*region| {
        //log.debug("Region descriptor: 0x{x}", .{region.descriptor.address.value});
        if (region.descriptor.size - region.allocated_size >= size) {
            const region_page_count = region.descriptor.size / page_size;
            const supposed_bitset_size = region_page_count / @bitSizeOf(MapEntry.BitsetBaseType);
            const bitset = region.get_bitset_extended();
            std.assert(bitset.len >= supposed_bitset_size);
            var region_allocated_page_count: u64 = 0;
            const allocated_page_count = region.allocated_size / page_size;

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
                                const offset = (bit + (start_index * @bitSizeOf(u64))) * page_size;
                                first_address = region.descriptor.address.value + offset;
                            }

                            bitset_elem.* = bitset_elem.* | (1 << bit);
                            region_allocated_page_count += 1;
                        }
                    }
                }
            }

            if (region_allocated_page_count == page_count) {
                const result = first_address;
                region.allocated_size += region_allocated_page_count * page_size;
                std.assert(result != 0);
                return PhysicalAddress.new(result);
            }

            std.assert(region.allocated_size + size > region.descriptor.size);
            std.assert(first_address != 0);
            const original_allocated_size = region.allocated_size - (region_allocated_page_count * page_size);
            const original_allocated_page_count = original_allocated_size / page_size;
            var byte = original_allocated_page_count / @bitSizeOf(u64);
            var bit = original_allocated_page_count % @bitSizeOf(u64);

            std.assert(region_allocated_page_count > 0);

            if (bit > 0) {
                while (bit < @bitSizeOf(u64)) : (bit += 1) {
                    bitset[byte] &= (~(@as(u64, 1) << @intCast(u6, bit)));
                    region_allocated_page_count -= 1;
                }
            }

            if (region_allocated_page_count >= 64) {
                TODO();
            }

            if (region_allocated_page_count > 0) {
                TODO();
            }

            region.allocated_size = original_allocated_size;
        }
    }

    @panic("allocation failed, no memory");
}

pub const MapEntry = struct {
    descriptor: PhysicalMemoryRegion,
    allocated_size: u64,
    type: Type,

    pub const Type = enum(u64) {
        usable = 0,
        reclaimable = 1,
        framebuffer = 2,
        kernel_and_modules = 3,
        reserved = 4,
    };
    pub const BitsetBaseType = u64;

    pub fn get_bitset_from_address_and_size(physical_address: PhysicalAddress, size: u64) []BitsetBaseType {
        const page_count = @divFloor(size, page_size);
        const bitset_len = std.div_ceil(u64, page_count, @bitSizeOf(BitsetBaseType)) catch unreachable;
        // INFO: this assumes the address is linearly mapped to the higher half
        const virtual_address = physical_address.to_higher_half_virtual_address();
        return virtual_address.access([*]BitsetBaseType)[0..bitset_len];
    }

    pub fn get_bitset_extended(entry: *MapEntry) []BitsetBaseType {
        return get_bitset_from_address_and_size(entry.descriptor.address, entry.descriptor.size);
    }

    pub fn setup_bitset(entry: *MapEntry) void {
        std.assert(!kernel.memory_initialized);
        const page_count = @divFloor(entry.allocated_size, page_size);
        const bitsize = @bitSizeOf(BitsetBaseType);
        const quotient = page_count / bitsize;
        const remainder_bitsize_max: u64 = bitsize - 1;
        const popcount = @popCount(remainder_bitsize_max);
        const remainder = @intCast(std.IntType(.unsigned, popcount), page_count % bitsize);

        const bitset = entry.get_bitset_extended();

        for (bitset[0..quotient]) |*bitset_elem| {
            bitset_elem.* = std.max_int(BitsetBaseType);
        }

        var remainder_i: @TypeOf(remainder) = 0;
        while (remainder_i < remainder) : (remainder_i += 1) {
            bitset[quotient] |= @as(u64, 1) << remainder_i;
        }
    }
};

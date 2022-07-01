const PhysicalAddressSpace = @This();

const common = @import("../common.zig");
const log = common.log.scoped(.PhysicalAddressSpace);
const TODO = common.TODO;
const PhysicalAddress = common.PhysicalAddress;
const PhysicalMemoryRegion = common.PhysicalMemoryRegion;
const IsHigherHalfMappedAlready = common.IsHigherHalfMappedAlready;

usable: []MapEntry,
reclaimable: []MapEntry,
framebuffer: []PhysicalMemoryRegion,
kernel_and_modules: []PhysicalMemoryRegion,
reserved: []PhysicalMemoryRegion,
page_size: u64,

pub fn new(comptime page_size: u64) PhysicalAddressSpace {
    return PhysicalAddressSpace{
        .usable = &.{},
        .reclaimable = &.{},
        .framebuffer = &.{},
        .kernel_and_modules = &.{},
        .reserved = &.{},
        .page_size = page_size,
    };
    //TODO(@src());
}

pub fn find_address(physical_address_space: *PhysicalAddressSpace, address: PhysicalAddress) void {
    _ = physical_address_space;
    _ = address;
    TODO(@src());
}

pub fn allocate(physical_address_space: *PhysicalAddressSpace, page_count: u64) ?PhysicalAddress {
    const take_hint = true;
    const page_size = physical_address_space.page_size;
    const size = page_count * page_size;
    // TODO: don't allocate if they are different regions (this can cause issues?)
    for (physical_address_space.usable) |*region| {
        if (region.descriptor.size - region.allocated_size >= size) {
            const region_page_count = region.descriptor.size / page_size;
            const supposed_bitset_size = region_page_count / @bitSizeOf(MapEntry.BitsetBaseType);
            const bitset = region.get_bitset_extended(page_size);
            common.runtime_assert(@src(), bitset.len >= supposed_bitset_size);
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
                common.runtime_assert(@src(), result != 0);
                return PhysicalAddress.new(result);
            }

            common.runtime_assert(@src(), region.allocated_size + size > region.descriptor.size);
            common.runtime_assert(@src(), first_address != 0);
            const original_allocated_size = region.allocated_size - (region_allocated_page_count * page_size);
            const original_allocated_page_count = original_allocated_size / page_size;
            var byte = original_allocated_page_count / @bitSizeOf(u64);
            var bit = original_allocated_page_count % @bitSizeOf(u64);

            common.runtime_assert(@src(), region_allocated_page_count > 0);

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

    pub fn get_bitset_from_address_and_size(physical_address: PhysicalAddress, size: u64, page_size: u64) []BitsetBaseType {
        const page_count = common.bytes_to_pages(size, page_size, .must_be_exact);
        const bitset_len = common.remainder_division_maybe_exact(page_count, @bitSizeOf(BitsetBaseType), .can_be_not_exact);
        return physical_address.access_kernel([*]BitsetBaseType)[0..bitset_len];
    }

    pub fn get_bitset_extended(entry: *MapEntry, page_size: u64) []BitsetBaseType {
        return get_bitset_from_address_and_size(entry.descriptor.address, entry.descriptor.size, page_size);
    }

    pub fn setup_bitset(entry: *MapEntry, page_size: u64) void {
        log.debug("Setting up bitset", .{});
        const page_count = common.bytes_to_pages(entry.allocated_size, page_size, .must_be_exact);
        log.debug("Set up bitset", .{});
        const bitsize = @bitSizeOf(BitsetBaseType);
        const quotient = page_count / bitsize;
        const remainder_bitsize_max: u64 = bitsize - 1;
        const popcount = @popCount(@TypeOf(remainder_bitsize_max), remainder_bitsize_max);
        const remainder = @intCast(common.IntType(.unsigned, popcount), page_count % bitsize);

        const bitset = entry.get_bitset_extended(page_size);

        for (bitset[0..quotient]) |*bitset_elem| {
            bitset_elem.* = common.max_int(BitsetBaseType);
        }

        var remainder_i: @TypeOf(remainder) = 0;
        while (remainder_i < remainder) : (remainder_i += 1) {
            bitset[quotient] |= @as(u64, 1) << remainder_i;
        }
    }
};

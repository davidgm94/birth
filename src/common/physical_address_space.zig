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

pub fn new() PhysicalAddressSpace {
    return PhysicalAddressSpace{
        .usable = &.{},
        .reclaimable = &.{},
        .framebuffer = &.{},
        .kernel_and_modules = &.{},
        .reserved = &.{},
    };
    //TODO(@src());
}

pub fn find_address(physical_address_space: *PhysicalAddressSpace, address: PhysicalAddress) void {
    _ = physical_address_space;
    _ = address;
    unreachable;
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

    pub fn get_bitset_from_address_and_size(physical_address: PhysicalAddress, size: u64, comptime is_higher_half_map_already: IsHigherHalfMappedAlready, comptime page_size: u64) []BitsetBaseType {
        const page_count = common.bytes_to_pages(size, page_size, .must_be_exact);
        const bitset_len = common.remainder_division_maybe_exact(page_count, @bitSizeOf(BitsetBaseType), .can_be_not_exact);
        return if (is_higher_half_map_already == .yes) physical_address.access_higher_half([*]BitsetBaseType)[0..bitset_len] else physical_address.access_identity([*]BitsetBaseType)[0..bitset_len];
    }

    pub fn get_bitset_extended(entry: *MapEntry, comptime is_higher_half_map_already: IsHigherHalfMappedAlready, comptime page_size: u64) []BitsetBaseType {
        return get_bitset_from_address_and_size(entry.descriptor.address, entry.descriptor.size, is_higher_half_map_already, page_size);
    }

    pub fn setup_bitset(entry: *MapEntry, comptime page_size: u64, comptime is_higher_half_map_already: IsHigherHalfMappedAlready) void {
        log.debug("Setting up bitset", .{});
        const page_count = common.bytes_to_pages(entry.allocated_size, page_size, .must_be_exact);
        log.debug("Set up bitset", .{});
        const bitsize = @bitSizeOf(BitsetBaseType);
        const quotient = page_count / bitsize;
        const remainder_bitsize_max: u64 = bitsize - 1;
        const popcount = @popCount(@TypeOf(remainder_bitsize_max), remainder_bitsize_max);
        const remainder = @intCast(common.IntType(.unsigned, popcount), page_count % bitsize);

        const bitset = entry.get_bitset_extended(is_higher_half_map_already, page_size);

        for (bitset[0..quotient]) |*bitset_elem| {
            bitset_elem.* = common.max_int(BitsetBaseType);
        }

        var remainder_i: @TypeOf(remainder) = 0;
        while (remainder_i < remainder) : (remainder_i += 1) {
            bitset[quotient] |= @as(u64, 1) << remainder_i;
        }
    }
};

const PhysicalAddressSpace = @This();

const common = @import("../common.zig");
const log = common.log.scoped(.PhysicalAddressSpace);
const TODO = common.TODO;
const PhysicalAddress = common.PhysicalAddress;
const PhysicalMemoryRegion = common.PhysicalMemoryRegion;

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
    pub fn get_bitset_from_address_and_size(physical_address: PhysicalAddress, size: u64) []BitsetBaseType {
        _ = physical_address;
        _ = size;
        TODO(@src());
    }
    pub fn get_bitset(entry: *MapEntry) []BitsetBaseType {
        return get_bitset_from_address_and_size(entry.descriptor.address, entry.descriptor.size);
    }
    pub fn setup_bitset(entry: *MapEntry, comptime page_size: u64) void {
        log.debug("Setting up bitset", .{});
        const page_count = common.bytes_to_pages(entry.allocated_size, page_size, .must_be_exact);
        log.debug("Set up bitset", .{});
        const bitsize = @bitSizeOf(BitsetBaseType);
        const quotient = page_count / bitsize;
        const remainder_bitsize_max: u64 = bitsize - 1;
        const popcount = @popCount(@TypeOf(remainder_bitsize_max), remainder_bitsize_max);
        const remainder = @intCast(common.IntType(.unsigned, popcount), page_count % bitsize);

        const bitset = entry.get_bitset();

        for (bitset[0..quotient]) |*bitset_elem| {
            bitset_elem.* = common.max_int(BitsetBaseType);
        }

        var remainder_i: @TypeOf(remainder) = 0;
        while (remainder_i < remainder) : (remainder_i += 1) {
            bitset[quotient] |= @as(u64, 1) << remainder_i;
        }
    }
};

const kernel = @import("kernel.zig");
const std = @import("std");

const log = kernel.log.scoped(.Memory);

pub const Region = struct {
    pub const Descriptor = struct {
        address: u64,
        size: u64,

        fn debug(descriptor: *const Descriptor) void {
            log.debug("(0x{x},\t0x{x},\t{})", .{ descriptor.address, descriptor.address + descriptor.size, descriptor.size });
        }
    };

    pub const DescriptorWithPermissions = struct {
        descriptor: Descriptor,
        read: bool,
        write: bool,
        execute: bool,
    };
};

pub const Map = struct {
    usable: []Entry,
    reclaimable: []Entry,
    framebuffer: []Region.Descriptor,
    kernel_and_modules: []Region.Descriptor,
    reserved: []Region.Descriptor,

    pub const Entry = struct {
        descriptor: Region.Descriptor,
        allocated_size: u64,
        type: Type,

        pub const BitsetBaseType = u64;

        pub const Type = enum(u64) {
            usable = 0,
            reclaimable = 1,
            framebuffer = 2,
            kernel_and_modules = 3,
            reserved = 4,
        };

        pub fn get_bitset(entry: *Entry) []BitsetBaseType {
            return get_bitset_from_address_and_size(entry.descriptor.address, entry.descriptor.size);
        }

        pub fn get_bitset_from_address_and_size(address: u64, size: u64) []BitsetBaseType {
            const page_count = kernel.bytes_to_pages(size, true);
            const bitset_len = kernel.remainder_division_maybe_exact(page_count, @bitSizeOf(BitsetBaseType), false);
            return @intToPtr([*]BitsetBaseType, address)[0..bitset_len];
        }

        pub fn setup_bitset(entry: *Entry, page_count: u64) void {
            entry.allocated_size += page_count * kernel.arch.page_size;

            const bitsize = @bitSizeOf(kernel.Memory.Map.Entry.BitsetBaseType);
            const quotient = page_count / bitsize;
            const remainder_bitsize_max: u64 = bitsize - 1;
            const popcount = @popCount(@TypeOf(remainder_bitsize_max), remainder_bitsize_max);
            const remainder = @intCast(std.meta.Int(.unsigned, popcount), page_count % bitsize);

            const bitset = entry.get_bitset();

            for (bitset[0..quotient]) |*bitset_elem| {
                bitset_elem.* = std.math.maxInt(kernel.Memory.Map.Entry.BitsetBaseType);
            }

            var remainder_i: @TypeOf(remainder) = 0;
            while (remainder_i < remainder) : (remainder_i += 1) {
                bitset[quotient] |= @as(u64, 1) << remainder_i;
            }
        }

        pub fn setup_bitset_alone(entry: *Entry) void {
            // Setup the bitset
            const bitset = entry.get_bitset();
            const bitset_size = bitset.len * @sizeOf(kernel.Memory.Map.Entry.BitsetBaseType);
            // INFO: this is separated since the bitset needs to be in a different page than the memory map
            const bitset_page_count = kernel.bytes_to_pages(bitset_size, false);
            entry.setup_bitset(bitset_page_count);
        }

        fn debug(entry: *Entry) void {
            log.debug("(0x{x},\t{})", .{ entry.descriptor.address, entry.descriptor.size });
        }
    };

    pub fn debug(map: *Map) void {
        log.debug("Usable", .{});
        for (map.usable) |region| {
            region.descriptor.debug();
        }
        log.debug("Reclaimable", .{});
        for (map.reclaimable) |region| {
            region.descriptor.debug();
        }
        log.debug("Framebuffer", .{});
        for (map.framebuffer) |region| {
            region.debug();
        }
        log.debug("Kernel and modules", .{});
        for (map.kernel_and_modules) |region| {
            region.debug();
        }
        log.debug("Reserved", .{});
        for (map.reserved) |region| {
            region.debug();
        }
    }
};

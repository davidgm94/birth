const std = @import("std.zig");
const Allocator = std.Allocator;

/// This list works when you are having multiple lists of the same type
pub fn ListItem(comptime T: type) type {
    return struct {
        previous: ?*@This() = null,
        next: ?*@This() = null,
        list: ?*List(T) = null,
        data: T, // = std.zeroes(T), This trips a bug in stage 1

        pub fn new(data: T) @This() {
            return @This(){
                .data = data,
            };
        }
    };
}

pub fn List(comptime T: type) type {
    return struct {
        first: ?*ListItem(T) = null,
        last: ?*ListItem(T) = null,
        count: u64 = 0,

        pub fn append(list: *@This(), list_item: *ListItem(T), item: T) !void {
            std.assert(list_item.previous == null);
            std.assert(list_item.next == null);
            std.assert(list_item.list == null);
            list_item.data = item;

            if (list.last) |last| {
                std.assert(list.first != null);
                std.assert(list.count > 0);
                last.next = list_item;
                list_item.previous = last;
                list.last = list_item;
            } else {
                std.assert(list.first == null);
                std.assert(list.count == 0);
                list.first = list_item;
                list.last = list_item;
            }

            list.count += 1;
            list_item.list = list;
        }

        pub fn remove(list: *@This(), list_item: *ListItem(T)) void {
            std.assert(list_item.list == list);
            if (list_item.previous) |previous| {
                previous.next = list_item.next;
            } else {
                list.first = list_item.next;
            }

            if (list_item.next) |next| {
                next.previous = list_item.previous;
            } else {
                // Last element of the list.
                list.last = list_item.previous;
            }

            list.count -= 1;
            list_item.list = null;
            std.assert(list.count == 0 or (list.first != null and list.last != null));
        }
    };
}

pub fn StableBuffer(comptime T: type, comptime bucket_size: comptime_int) type {
    const IntType = switch (bucket_size) {
        8 => u8,
        16 => u16,
        32 => u32,
        64 => u64,
        else => unreachable,
    };

    const IntShifterType = std.IntType(.unsigned, @ctz(u64, @bitSizeOf(IntType)));

    const bitset_size = bucket_size / @bitSizeOf(IntType);
    std.assert(bucket_size % @bitSizeOf(IntType) == 0);

    return struct {
        first: ?*Bucket = null,
        last: ?*Bucket = null,
        bucket_count: u64 = 0,
        element_count: u64 = 0,

        pub const Bucket = struct {
            bitset: [bitset_size]IntType = [1]IntType{0} ** bitset_size,
            count: u64 = 0,
            previous: ?*@This() = null,
            next: ?*@This() = null,
            data: [bucket_size]T,

            pub const size = bucket_size;

            pub const FindIndexResult = struct {
                bitset_index: u32,
                bit_index: u32,
            };

            pub fn allocate_index(bucket: *Bucket) u64 {
                std.assert(bucket.count + 1 <= bucket_size);

                for (bucket.bitset) |*bitset_elem, bitset_i| {
                    // @ZigBug using a comptime var here ends with an infinite loop
                    var bit_i: u8 = 0;
                    while (bit_i < @bitSizeOf(IntType)) : (bit_i += 1) {
                        if (bitset_elem.* & (@as(@TypeOf(bitset_elem.*), 1) << @intCast(IntShifterType, bit_i)) == 0) {
                            bitset_elem.* |= @as(@TypeOf(bitset_elem.*), 1) << @intCast(IntShifterType, bit_i);
                            bucket.count += 1;
                            return bitset_i * @bitSizeOf(IntType) + bit_i;
                        }
                    }
                }

                @panic("wtf");
            }
        };

        pub fn add_one(stable_buffer: *@This(), allocator: Allocator) std.Allocator.Error!*T {
            if (stable_buffer.first == null) {
                const first_bucket = try allocator.create(Bucket);
                first_bucket.* = Bucket{ .data = std.zeroes([bucket_size]T) };
                stable_buffer.first = first_bucket;
                first_bucket.bitset[0] = 1;
                stable_buffer.bucket_count += 1;
                stable_buffer.element_count += 1;

                return &first_bucket.data[0];
            } else {
                var iterator = stable_buffer.first;
                var last: ?*Bucket = null;
                while (iterator) |next| {
                    if (next.count < bucket_size) {
                        const index = next.allocate_index();
                        stable_buffer.element_count += 1;
                        const result = &next.data[index];
                        return result;
                    }

                    last = next;
                    iterator = next.next;
                }

                @panic("buffer end");
            }
        }
    };
}

const common = @import("common");
const Allocator = common.CustomAllocator;
const assert = common.assert;
const div_ceil = common.div_ceil;
const log = common.log.scoped(.List);
const zeroes = common.zeroes;

/// This list works when you are having multiple lists of the same type
pub fn ListItem(comptime T: type) type {
    return struct {
        previous: ?*@This() = null,
        next: ?*@This() = null,
        list: ?*List(T) = null,
        data: T, // = zeroes(T), This trips a bug in stage 1

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
            assert(list_item.previous == null);
            assert(list_item.next == null);
            assert(list_item.list == null);
            list_item.data = item;

            if (list.last) |last| {
                assert(list.first != null);
                assert(list.count > 0);
                last.next = list_item;
                list_item.previous = last;
                list.last = list_item;
            } else {
                assert(list.first == null);
                assert(list.count == 0);
                list.first = list_item;
                list.last = list_item;
            }

            list.count += 1;
            list_item.list = list;
        }

        pub fn remove(list: *@This(), list_item: *ListItem(T)) void {
            assert(list_item.list == list);
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
            assert(list.count == 0 or (list.first != null and list.last != null));
        }
    };
}

pub fn StableBuffer(comptime T: type, comptime bucket_size: comptime_int) type {

    //const IntShifterType = IntType(.unsigned, @ctz(@bitSizeOf(IntType)));

    //const bitset_size = bucket_size / @bitSizeOf(IntType);
    //assert(bucket_size % @bitSizeOf(IntType) == 0);

    return struct {
        first: ?*Bucket = null,
        last: ?*Bucket = null,
        bucket_count: u64 = 0,
        element_count: u64 = 0,

        pub const Bucket = struct {
            count: u64 = 0,
            previous: ?*@This() = null,
            next: ?*@This() = null,
            data: [bucket_size]T,

            pub const size = bucket_size;

            // TODO: make this good
            pub fn allocate_indices(bucket: *Bucket, count: u64) u64 {
                assert(count == 1);
                if (bucket.count + count <= bucket_size) {
                    const result = bucket.count;
                    bucket.count += count;
                    return result;
                }

                @panic("wtf");
            }
        };

        pub fn add_one(stable_buffer: *@This(), allocator: Allocator) Allocator.Error!*T {
            if (stable_buffer.first == null) {
                const first_bucket = try allocator.create(Bucket);
                first_bucket.* = Bucket{ .data = zeroes([bucket_size]T) };
                const index = first_bucket.allocate_indices(1);
                stable_buffer.first = first_bucket;
                stable_buffer.bucket_count += 1;
                stable_buffer.element_count += 1;

                return &first_bucket.data[index];
            } else {
                var iterator = stable_buffer.first;
                var last: ?*Bucket = null;
                while (iterator) |next| {
                    if (next.count < bucket_size) {
                        const index = next.allocate_indices(1);
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

        pub fn add_many(stable_buffer: *@This(), allocator: Allocator, count: u64) Allocator.Error![]T {
            if (stable_buffer.first == null) {
                const bucket_count = div_ceil(u64, count, Bucket.size) catch unreachable;
                //assert(bucket_count == 1);
                const buckets = try allocator.allocate_many(Bucket, bucket_count);

                var elements_allocated: u64 = count;
                var i: u64 = 0;
                var maybe_previous: ?*Bucket = null;

                while (elements_allocated > Bucket.size) : ({
                    elements_allocated -= Bucket.size;
                    i += 1;
                }) {
                    const bucket = &buckets[i];
                    defer {
                        if (maybe_previous) |previous| {
                            previous.next = bucket;
                        }
                        maybe_previous = bucket;
                    }

                    bucket.* = Bucket{ .count = Bucket.size, .previous = maybe_previous, .data = zeroes([bucket_size]T) };
                }

                const last_bucket = &buckets[i];
                last_bucket.* = Bucket{ .count = elements_allocated, .previous = maybe_previous, .data = zeroes([bucket_size]T) };

                stable_buffer.bucket_count += buckets.len;
                stable_buffer.element_count += count;
                stable_buffer.first = &buckets[0];
                stable_buffer.last = last_bucket;

                return stable_buffer.first.?.data[0..count];
            } else {
                @panic("Wtfffffffffffffff");
                //var iterator = stable_buffer.first;
                //var last: ?*Bucket = null;
                //while (iterator) |next| {
                //if (next.count < bucket_size) {
                //const index = next.allocate_indices(count);
                //stable_buffer.element_count += 1;
                //const result = next.data[index .. index + count];
                //return result;
                //}

                //last = next;
                //iterator = next.next;
                //}

                //@panic("buffer end");
            }
        }
    };
}

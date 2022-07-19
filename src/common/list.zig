const common = @import("../common.zig");
const Allocator = common.Allocator;
const TODO = common.TODO;

/// This list works when you are having multiple lists of the same type
pub fn ListItem(comptime T: type) type {
    return struct {
        previous: ?*@This(),
        next: ?*@This(),
        list: ?*List(T),
        data: T,
    };
}

pub fn List(comptime T: type) type {
    return struct {
        first: ?*ListItem(T) = null,
        last: ?*ListItem(T) = null,
        count: u64 = 0,

        pub fn append(list: *@This(), list_item: *ListItem(T), item: T) !void {
            common.runtime_assert(@src(), list_item.previous == null);
            common.runtime_assert(@src(), list_item.next == null);
            common.runtime_assert(@src(), list_item.list == null);
            list_item.data = item;

            if (list.last) |last| {
                common.runtime_assert(@src(), list.first != null);
                common.runtime_assert(@src(), list.count > 0);
                last.next = list_item;
                list_item.previous = last;
                list.last = list_item;
            } else {
                common.runtime_assert(@src(), list.first == null);
                common.runtime_assert(@src(), list.count == 0);
                list.first = list_item;
                list.last = list_item;
            }

            list.count += 1;
            list_item.list = list;
        }

        pub fn remove(list: *@This(), list_item: *ListItem(T)) void {
            common.runtime_assert(@src(), list_item.list == list);
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
            common.runtime_assert(@src(), list.count == 0 or (list.first != null and list.last != null));
        }
    };
}

pub fn StableBuffer(comptime T: type, comptime bucket_size: comptime_int) type {
    common.comptime_assert(bucket_size % 64 == 0);
    return struct {
        first: ?*Bucket = null,
        last: ?*Bucket = null,
        bucket_count: u64 = 0,
        element_count: u64 = 0,

        pub const Bucket = struct {
            previous: ?*@This() = null,
            next: ?*@This() = null,
            bitset: [bitset_size]u64 = [1]u64{0} ** bitset_size,
            data: [bitset_size]T,

            pub const bitset_size = bucket_size / 64;
        };

        pub fn add_one(stable_buffer: *@This(), allocator: Allocator) common.Allocator.Error!*T {
            if (stable_buffer.first == null) {
                const first_bucket = try allocator.create(Bucket);
                stable_buffer.first = first_bucket;
                for (first_bucket.bitset) |bitset_elem| {
                    common.runtime_assert(@src(), bitset_elem == 0);
                }
                first_bucket.bitset[0] = 1;
                stable_buffer.bucket_count += 1;
                stable_buffer.element_count += 1;

                return &first_bucket.data[0];
            } else {
                TODO(@src());
            }
        }
    };
}

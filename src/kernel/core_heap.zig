const kernel = @import("kernel.zig");
const log = kernel.log.scoped(.CoreHeap);
const TODO = kernel.TODO;
const Physical = kernel.Physical;
const Virtual = kernel.Virtual;

const Heap = @This();

pub const AllocationResult = struct {
    physical: u64,
    virtual: u64,
    asked_size: u64,
    given_size: u64,
};

const Region = struct {
    virtual: Virtual.Address,
    size: u64,
    allocated: u64,
};

regions: [region_count]Region,
// TODO: use another synchronization primitive
lock: kernel.Spinlock,

const region_size = 2 * kernel.mb;
const region_count = kernel.core_memory_region.size / region_size;

pub inline fn allocate(heap: *Heap, comptime T: type) ?*T {
    return @intToPtr(*T, (heap.allocate_extended(@sizeOf(T), @alignOf(T)) orelse return null).value);
}

pub inline fn allocate_many(heap: *Heap, comptime T: type, count: u64) ?[]T {
    return @intToPtr([*]T, (heap.allocate_extended(@sizeOf(T) * count, @alignOf(T)) orelse return null).value)[0..count];
}

pub fn allocate_extended(heap: *Heap, size: u64, alignment: u64) ?Virtual.Address {
    log.debug("Heap: 0x{x}", .{@ptrToInt(heap)});
    kernel.assert(@src(), size < region_size);
    heap.lock.acquire();
    defer heap.lock.release();
    const region = blk: {
        for (heap.regions) |*region| {
            if (region.size > 0) {
                region.allocated = kernel.align_forward(region.allocated, alignment);
                kernel.assert(@src(), (region.size - region.allocated) >= size);
                break :blk region;
            } else {
                log.debug("have to allocate region", .{});
                const virtual_address = kernel.address_space.allocate(region_size) orelse return null;

                region.* = Region{
                    .virtual = virtual_address,
                    .size = region_size,
                    .allocated = 0,
                };

                break :blk region;
            }
        }

        @panic("unreachableeee");
    };

    const result_address = region.virtual.value + region.allocated;
    region.allocated += size;

    return Virtual.Address.new(result_address);
}

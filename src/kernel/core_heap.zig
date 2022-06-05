const kernel = @import("kernel.zig");
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
    physical: u64,
    virtual: u64,
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

pub inline fn allocate_many(heap: *Heap, comptime T: type, count: u64) []T {
    return @intToPtr([*]T, (heap.allocate_extended(@sizeOf(T) * count, @alignOf(T)) orelse return null).value)[0..count];
}

pub fn allocate_extended(heap: *Heap, size: u64, alignment: u64) ?Virtual.Address {
    kernel.assert(@src(), size < region_size);
    heap.lock.acquire();
    defer heap.lock.release();
    const region = blk: {
        for (heap.regions) |*region, region_index| {
            if (region.size > 0) {
                region.allocated = kernel.align_forward(region.allocated, alignment);
                kernel.assert(@src(), (region.size - region.allocated) >= size);
                break :blk region;
            } else {
                const physical_allocation = kernel.Physical.Memory.allocate_pages(kernel.bytes_to_pages(region_size, true)) orelse return null;
                const physical_region = Physical.Memory.Region{
                    .address = physical_allocation,
                    .size = region_size,
                };
                const virtual_base = Virtual.Address.new(kernel.core_memory_region.address.value + (region_size * region_index));
                physical_region.map(&kernel.address_space, virtual_base);

                region.* = Region{
                    .physical = physical_region.address.value,
                    .virtual = virtual_base.value,
                    .size = region_size,
                    .allocated = 0,
                };

                break :blk region;
            }
        }

        @panic("unreachableeee");
    };

    // TODO: move this when we don't allocate a new region
    //const is_aligned = kernel.is_aligned(region.virtual + region.allocated, alignment);
    //if (!is_aligned) {
    //}

    const result_address = region.virtual + region.allocated;
    region.allocated += size;

    return Virtual.Address.new(result_address);
}

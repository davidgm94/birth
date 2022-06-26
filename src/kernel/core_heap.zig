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

pub const Region = struct {
    virtual: Virtual.Address,
    size: u64,
    allocated: u64,
};

regions: [region_count]Region,
// TODO: use another synchronization primitive
lock: kernel.Spinlock,
allocator: kernel.Allocator,

const region_size = 2 * kernel.mb;
pub const region_count = kernel.core_memory_region.size / region_size;

pub fn init(heap: *Heap) void {
    heap.allocator.ptr = heap;
    heap.allocator.vtable = &allocator_interface.vtable;
}

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

var allocator_interface = struct {
    vtable: kernel.Allocator.VTable = .{
        .alloc = @ptrCast(fn alloc(heap: *anyopaque, len: usize, ptr_align: u29, len_align: u29, return_address: usize) kernel.Allocator.Error![]u8, alloc),
        .resize = @ptrCast(fn resize(heap: *anyopaque, old_mem: []u8, old_align: u29, new_size: usize, len_align: u29, return_address: usize) ?usize, resize),
        .free = @ptrCast(fn free(heap: *anyopaque, old_mem: []u8, old_align: u29, return_address: usize) void, free),
    },

    fn alloc(heap: *Heap, len: usize, ptr_align: u29, len_align: u29, return_address: usize) kernel.Allocator.Error![]u8 {
        _ = heap;
        _ = len;
        _ = ptr_align;
        _ = len_align;
        _ = return_address;

        TODO(@src());
    }
    fn resize(heap: *Heap, old_mem: []u8, old_align: u29, new_size: usize, len_align: u29, return_address: usize) ?usize {
        _ = heap;
        _ = old_mem;
        _ = old_align;
        _ = new_size;
        _ = len_align;
        _ = return_address;
        TODO(@src());
    }
    fn free(heap: *Heap, old_mem: []u8, old_align: u29, return_address: usize) void {
        _ = heap;
        _ = old_mem;
        _ = old_align;
        _ = return_address;
        TODO(@src());
    }
}{};

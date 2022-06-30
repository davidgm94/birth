const kernel = @import("root");
const common = @import("common");
const log = common.log.scoped(.CoreHeap);
const TODO = common.TODO;
const Allocator = common.Allocator;
const VirtualAddress = common.VirtualAddress;
const VirtualAddressSpace = common.VirtualAddressSpace;

const Heap = @This();

pub const Region = struct {
    virtual: VirtualAddress,
    size: u64,
    allocated: u64,
};

allocator: Allocator,
// TODO: use another synchronization primitive
lock: kernel.Spinlock,
regions: [region_count]Region,
virtual_address_space: *VirtualAddressSpace,

const region_size = 2 * common.mb;
pub const region_count = kernel.core_memory_region.size / region_size;

pub fn init(heap: *Heap, address_space: *VirtualAddressSpace) void {
    heap.allocator.ptr = heap;
    heap.allocator.vtable = &allocator_interface.vtable;
    heap.virtual_address_space = address_space;
}

var allocator_interface = struct {
    vtable: Allocator.VTable = .{
        .alloc = @ptrCast(fn alloc(heap: *anyopaque, len: usize, ptr_align: u29, len_align: u29, return_address: usize) Allocator.Error![]u8, alloc),
        .resize = @ptrCast(fn resize(heap: *anyopaque, old_mem: []u8, old_align: u29, new_size: usize, len_align: u29, return_address: usize) ?usize, resize),
        .free = @ptrCast(fn free(heap: *anyopaque, old_mem: []u8, old_align: u29, return_address: usize) void, free),
    },

    fn alloc(heap: *Heap, size: usize, ptr_align: u29, len_align: u29, return_address: usize) Allocator.Error![]u8 {
        heap.lock.acquire();
        defer heap.lock.release();
        common.runtime_assert(@src(), size < region_size);

        log.debug("Asked allocation: Size: {}. Pointer alignment: {}. Length alignment: {}. Return address: 0x{x}", .{ size, ptr_align, len_align, return_address });
        var alignment: u64 = len_align;
        if (ptr_align > alignment) alignment = ptr_align;

        const region = blk: {
            for (heap.regions) |*region| {
                if (region.size > 0) {
                    region.allocated = common.align_forward(region.allocated, alignment);
                    common.runtime_assert(@src(), (region.size - region.allocated) >= size);
                    break :blk region;
                } else {
                    log.debug("have to allocate region", .{});
                    // TODO: revisit arguments
                    const allocation_slice = heap.virtual_address_space.allocator.allocBytes(0, region_size, 0, 0) catch return Allocator.Error.OutOfMemory;

                    region.* = Region{
                        .virtual = VirtualAddress.new(@ptrToInt(allocation_slice.ptr)),
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
        return @intToPtr([*]u8, result_address)[0..size];
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

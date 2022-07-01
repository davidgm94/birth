const Heap = @This();
const common = @import("../common.zig");
const log = common.log.scoped(.CoreHeap);
const TODO = common.TODO;
const Allocator = common.Allocator;
const VirtualAddress = common.VirtualAddress;
const VirtualAddressSpace = common.VirtualAddressSpace;
const Spinlock = common.arch.Spinlock;

pub const Region = struct {
    virtual: VirtualAddress,
    size: u64,
    allocated: u64,
};

allocator: Allocator,
// TODO: use another synchronization primitive
lock: Spinlock,
regions: [region_count]Region,
virtual_address_space: ?*VirtualAddressSpace,
bootstrap_region: Region,

const region_size = 2 * common.mb;
pub const region_count = 0x1000_0000 / region_size;

pub fn init(heap: *Heap, bootstrapping_memory: []u8) void {
    heap.allocator.ptr = heap;
    heap.allocator.vtable = &allocator_interface.vtable;
    heap.virtual_address_space = null;
    heap.bootstrap_region = Region{
        .virtual = VirtualAddress.new(@ptrToInt(bootstrapping_memory.ptr)),
        .size = bootstrapping_memory.len,
        .allocated = 0,
    };
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

        // TODO: check if the region has enough available space
        if (heap.virtual_address_space) |virtual_address_space| {
            const region = blk: {
                for (heap.regions) |*region| {
                    if (region.size > 0) {
                        region.allocated = common.align_forward(region.allocated, alignment);
                        common.runtime_assert(@src(), (region.size - region.allocated) >= size);
                        break :blk region;
                    } else {
                        // TODO: revisit arguments @MaybeBug
                        const allocation_slice = virtual_address_space.allocator.allocBytes(0, region_size, 0, 0) catch return Allocator.Error.OutOfMemory;

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
        } else {
            heap.bootstrap_region.allocated = common.align_forward(heap.bootstrap_region.allocated, alignment);
            log.debug("Allocated: {}. Size: {}", .{ heap.bootstrap_region.allocated, heap.bootstrap_region.size });
            common.runtime_assert(@src(), (heap.bootstrap_region.size - heap.bootstrap_region.allocated) >= size);

            const result_address = heap.bootstrap_region.virtual.value + heap.bootstrap_region.allocated;
            heap.bootstrap_region.allocated += size;
            return @intToPtr([*]u8, result_address)[0..size];
        }
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

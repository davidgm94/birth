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

kernel_allocator: Allocator,
user_allocator: Allocator,
// TODO: use another synchronization primitive
lock: Spinlock,
regions: [region_count]Region,
virtual_address_space: ?*VirtualAddressSpace,

const region_size = 2 * common.mb;
pub const region_count = 0x1000_0000 / region_size;

pub fn init(heap: *Heap) void {
    heap.kernel_allocator.ptr = heap;
    heap.kernel_allocator.vtable = &kernel_allocator_interface.vtable;
    heap.user_allocator.ptr = heap;
    heap.user_allocator.vtable = &user_allocator_interface.vtable;
    heap.virtual_address_space = null;
}

const user_allocator_interface = AllocatorInterface(.user){};
const kernel_allocator_interface = AllocatorInterface(.kernel){};

fn AllocatorInterface(comptime privilege_level: common.PrivilegeLevel) type {
    return struct {
        vtable: Allocator.VTable = .{
            .alloc = @ptrCast(fn alloc(heap: *anyopaque, len: usize, ptr_align: u29, len_align: u29, return_address: usize) Allocator.Error![]u8, alloc),
            .resize = @ptrCast(fn resize(heap: *anyopaque, old_mem: []u8, old_align: u29, new_size: usize, len_align: u29, return_address: usize) ?usize, resize),
            .free = @ptrCast(fn free(heap: *anyopaque, old_mem: []u8, old_align: u29, return_address: usize) void, free),
        },

        const flags = VirtualAddressSpace.Flags{
            .write = true,
            .user = privilege_level == .user,
        };

        fn alloc(heap: *Heap, size: usize, ptr_align: u29, len_align: u29, return_address: usize) Allocator.Error![]u8 {
            heap.lock.acquire();
            defer heap.lock.release();

            log.debug("Asked allocation: Size: {}. Pointer alignment: {}. Length alignment: {}. Return address: 0x{x}", .{ size, ptr_align, len_align, return_address });

            var alignment: u64 = len_align;
            if (ptr_align > alignment) alignment = ptr_align;

            // TODO: check if the region has enough available space
            const virtual_address_space = heap.virtual_address_space orelse unreachable;
            if (size < region_size) {
                const region = blk: {
                    for (heap.regions) |*region| {
                        if (region.size > 0) {
                            region.allocated = common.align_forward(region.allocated, alignment);
                            common.runtime_assert(@src(), (region.size - region.allocated) >= size);
                            break :blk region;
                        } else {
                            // TODO: revisit arguments @MaybeBug

                            region.* = Region{
                                .virtual = try virtual_address_space.allocate(region_size, null, flags),
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
                const allocation_size = common.align_forward(size, virtual_address_space.physical_address_space.page_size);
                const virtual_address = try virtual_address_space.allocate(allocation_size, null, flags);
                log.debug("Big allocation happened!", .{});
                return virtual_address.access([*]u8)[0..size];
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
    };
}

const Heap = @This();
const common = @import("../common.zig");
const context = @import("context");
const log = common.log.scoped(.Heap);
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
regions: [region_count]Region,
lock: Spinlock,

const region_size = 2 * common.mb;
pub const region_count = 0x1000_0000 / region_size;

pub fn new(virtual_address_space: *VirtualAddressSpace) Heap {
    return Heap{
        .allocator = Allocator{
            .ptr = virtual_address_space,
            .vtable = &vtable,
        },
        .regions = common.zeroes([region_count]Region),
        .lock = Spinlock.new(),
    };
}

fn alloc(virtual_address_space: *VirtualAddressSpace, size: usize, ptr_align: u29, len_align: u29, return_address: usize) Allocator.Error![]u8 {
    virtual_address_space.heap.lock.acquire();
    defer virtual_address_space.heap.lock.release();

    log.debug("Asked allocation: Size: {}. Pointer alignment: {}. Length alignment: {}. Return address: 0x{x}", .{ size, ptr_align, len_align, return_address });

    var alignment: u64 = len_align;
    if (ptr_align > alignment) alignment = ptr_align;

    const flags = VirtualAddressSpace.Flags{
        .write = true,
        .user = virtual_address_space.privilege_level == .user,
    };

    // TODO: check if the region has enough available space
    if (size < region_size) {
        const region = blk: {
            for (virtual_address_space.heap.regions) |*region| {
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
        const allocation_size = common.align_forward(size, context.page_size);
        const virtual_address = try virtual_address_space.allocate(allocation_size, null, flags);
        log.debug("Big allocation happened!", .{});
        return virtual_address.access([*]u8)[0..size];
    }
}

fn resize(virtual_address_space: *VirtualAddressSpace, old_mem: []u8, old_align: u29, new_size: usize, len_align: u29, return_address: usize) ?usize {
    _ = virtual_address_space;
    _ = old_mem;
    _ = old_align;
    _ = new_size;
    _ = len_align;
    _ = return_address;
    TODO(@src());
}

fn free(virtual_address_space: *VirtualAddressSpace, old_mem: []u8, old_align: u29, return_address: usize) void {
    _ = virtual_address_space;
    _ = old_mem;
    _ = old_align;
    _ = return_address;
    TODO(@src());
}

const vtable: Allocator.VTable = .{
    .alloc = @ptrCast(fn alloc(context: *anyopaque, len: usize, ptr_align: u29, len_align: u29, return_address: usize) Allocator.Error![]u8, alloc),
    .resize = @ptrCast(fn resize(context: *anyopaque, old_mem: []u8, old_align: u29, new_size: usize, len_align: u29, return_address: usize) ?usize, resize),
    .free = @ptrCast(fn free(context: *anyopaque, old_mem: []u8, old_align: u29, return_address: usize) void, free),
};

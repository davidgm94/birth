const Heap = @This();

const std = @import("../common/std.zig");

const arch = @import("arch.zig");
const crash = @import("crash.zig");
const context = @import("context.zig");
const VirtualAddress = @import("virtual_address.zig");
const VirtualAddressSpace = @import("virtual_address_space.zig");

const log = std.log.scoped(.Heap);
const Spinlock = arch.Spinlock;
const TODO = crash.TODO;

pub const Region = struct {
    virtual: VirtualAddress,
    size: u64,
    allocated: u64,
};

allocator: std.Allocator,
regions: [region_count]Region,
lock: Spinlock,

const region_size = 2 * std.mb;
pub const region_count = 0x1000_0000 / region_size;

pub fn new(virtual_address_space: *VirtualAddressSpace) Heap {
    return Heap{
        .allocator = std.Allocator{
            .ptr = virtual_address_space,
            .vtable = &vtable,
        },
        .regions = std.zeroes([region_count]Region),
        .lock = Spinlock.new(),
    };
}

fn alloc(virtual_address_space: *VirtualAddressSpace, size: usize, ptr_align: u29, len_align: u29, return_address: usize) std.Allocator.Error![]u8 {
    virtual_address_space.heap.lock.acquire();
    defer virtual_address_space.heap.lock.release();
    std.assert(virtual_address_space.lock.status == 0);

    log.debug("Asked allocation: Size: {}. Pointer alignment: {}. Length alignment: {}. Return address: 0x{x}", .{ size, ptr_align, len_align, return_address });

    var alignment: u64 = len_align;
    if (ptr_align > alignment) alignment = ptr_align;

    const flags = VirtualAddressSpace.Flags{
        .write = true,
        .user = virtual_address_space.privilege_level == .user,
    };

    if (flags.user and !virtual_address_space.is_current()) {
        // TODO: currently the Zig allocator somehow dereferences memory so allocating memory for another address space make this not viable
        @panic("trying to allocate stuff for userspace from another address space");
    }

    // TODO: check if the region has enough available space
    if (size < region_size) {
        const region = blk: {
            for (virtual_address_space.heap.regions) |*region| {
                if (region.size > 0) {
                    const aligned_allocated = region.virtual.offset(region.allocated).aligned_forward(alignment).value - region.virtual.value;
                    if (region.size < aligned_allocated + size) continue;
                    //std.assert((region.size - region.allocated) >= size);
                    region.allocated = aligned_allocated;
                    break :blk region;
                } else {
                    // TODO: revisit arguments @MaybeBug

                    region.* = Region{
                        .virtual = try virtual_address_space.allocate(region_size, null, flags),
                        .size = region_size,
                        .allocated = 0,
                    };

                    // Avoid footguns
                    std.assert(std.is_aligned(region.virtual.value, alignment));

                    break :blk region;
                }
            }

            @panic("heap out of memory");
        };
        const result_address = region.virtual.value + region.allocated;
        region.allocated += size;
        return @intToPtr([*]u8, result_address)[0..size];
    } else {
        const allocation_size = std.align_forward(size, context.page_size);
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

const vtable: std.Allocator.VTable = .{
    .alloc = @ptrCast(fn alloc(context: *anyopaque, len: usize, ptr_align: u29, len_align: u29, return_address: usize) std.Allocator.Error![]u8, alloc),
    .resize = @ptrCast(fn resize(context: *anyopaque, old_mem: []u8, old_align: u29, new_size: usize, len_align: u29, return_address: usize) ?usize, resize),
    .free = @ptrCast(fn free(context: *anyopaque, old_mem: []u8, old_align: u29, return_address: usize) void, free),
};

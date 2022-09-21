const Heap = @This();

const std = @import("../common/std.zig");

const arch = @import("arch/common.zig");
const crash = @import("crash.zig");
const kernel = @import("kernel.zig");
const VirtualAddress = @import("virtual_address.zig");
const VirtualAddressSpace = @import("virtual_address_space.zig");

const log = std.log.scoped(.Heap);
const Spinlock = @import("spinlock.zig");
const TODO = crash.TODO;
const Allocator = std.CustomAllocator;

pub const Region = struct {
    virtual: VirtualAddress = VirtualAddress{ .value = 0 },
    size: u64 = 0,
    allocated: u64 = 0,
};

allocator: Allocator = undefined,
regions: [region_count]Region = [1]Region{.{}} ** region_count,
lock: Spinlock = .{},

const region_size = 1024 * arch.page_size;
pub const region_count = 0x1000_0000 / region_size;

pub fn new(virtual_address_space: *VirtualAddressSpace) Heap {
    return Heap{
        .allocator = Allocator{
            .context = virtual_address_space,
            .callback_allocate = allocate_function,
        },
        .regions = std.zeroes([region_count]Region),
        .lock = Spinlock{},
    };
}

fn allocate_function(allocator: Allocator, size: u64, alignment: u64) Allocator.Error!Allocator.Result {
    const virtual_address_space = @ptrCast(?*VirtualAddressSpace, allocator.context) orelse unreachable;
    log.debug("Acquiring -- allocate", .{});
    virtual_address_space.heap.lock.acquire();
    defer {
        log.debug("Releasing -- allocate", .{});
        virtual_address_space.heap.lock.release();
    }
    std.assert(virtual_address_space.lock.status == 0);

    log.debug("Asked allocation: Size: {}. Alignment: {}", .{ size, alignment });

    const flags = VirtualAddressSpace.Flags{
        .write = true,
        .user = virtual_address_space.privilege_level == .user,
    };

    if (flags.user and !virtual_address_space.is_current()) {
        // TODO: currently the Zig allocator somehow dereferences memory so allocating memory for another address space make this not viable
        @panic("trying to allocate stuff for userspace from another address space");
    }

    //// TODO: check if the region has enough available space
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
                        .virtual = virtual_address_space.allocate(region_size, null, flags) catch |err| {
                            log.err("Error allocating small memory from VAS: {}", .{err});
                            return std.Allocator.Error.OutOfMemory;
                        },
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
        log.debug("Result address: 0x{x}", .{result_address});
        if (kernel.config.safe_slow) {
            std.assert(virtual_address_space.translate_address(VirtualAddress.new(std.align_backward(result_address, 0x1000))) != null);
        }
        region.allocated += size;

        return .{
            .address = result_address,
            .size = size,
        };
    } else {
        const allocation_size = std.align_forward(size, arch.page_size);
        const virtual_address = virtual_address_space.allocate(allocation_size, null, flags) catch |err| {
            log.err("Error allocating big chunk from VAS: {}", .{err});
            return std.Allocator.Error.OutOfMemory;
        };
        log.debug("Big allocation happened!", .{});

        return .{
            .address = virtual_address.value,
            .size = size,
        };
    }
}

fn resize(virtual_address_space: *VirtualAddressSpace, old_mem: []u8, old_align: u29, new_size: usize, len_align: u29, return_address: usize) ?usize {
    _ = virtual_address_space;
    _ = old_mem;
    _ = old_align;
    _ = new_size;
    _ = len_align;
    _ = return_address;
    TODO();
}

fn free(virtual_address_space: *VirtualAddressSpace, old_mem: []u8, old_align: u29, return_address: usize) void {
    _ = virtual_address_space;
    _ = old_mem;
    _ = old_align;
    _ = return_address;
    TODO();
}

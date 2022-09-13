const PhysicalAddressSpace = @This();

const std = @import("../common/std.zig");

const arch = @import("arch/common.zig");
const crash = @import("crash.zig");
const kernel = @import("kernel.zig");
const PhysicalAddress = @import("physical_address.zig");
const PhysicalMemoryRegion = @import("physical_memory_region.zig");
const Spinlock = @import("spinlock.zig");

const log = std.log.scoped(.PhysicalAddressSpace);
const TODO = crash.TODO;

zero_free_list: List = .{},
free_list: List = .{},
lock: Spinlock = .{},

pub fn allocate_pages(physical_address_space: *PhysicalAddressSpace, comptime page_size: u64, page_count: u64, flags: Flags) ?PhysicalMemoryRegion {
    physical_address_space.lock.acquire();
    defer physical_address_space.lock.release();

    var node_ptr = if (flags.zeroed) physical_address_space.zero_free_list.first else physical_address_space.free_list.first;
    const size = page_size * page_count;

    while (node_ptr) |node| : (node_ptr = node.next) {
        if (node.descriptor.size > size) {
            const allocated_region = PhysicalMemoryRegion{
                .address = node.descriptor.address,
                .size = size,
            };
            node.descriptor.address.value += size;
            node.descriptor.size -= size;

            return allocated_region;
        } else if (node.descriptor.size == size) {
            const allocated_region = node.descriptor;
            if (node.previous) |previous| previous.next = node.next;
            if (node.next) |next| next.previous = node.previous;

            return allocated_region;
        }
    }

    return null;
}

pub fn free_pages(physical_address_space: *PhysicalAddressSpace, comptime page_size: u64, page_count: u64, flags: Flags) void {
    physical_address_space.lock.acquire();
    defer physical_address_space.lock.release();
    _ = physical_address_space;
    _ = page_size;
    _ = page_count;
    _ = flags;

    @panic("todo free pages");
}

const List = struct {
    first: ?*FreePhysicalRegion = null,
    last: ?*FreePhysicalRegion = null,
    count: u64 = 0,
};

const Flags = packed struct(u64) {
    zeroed: bool = false,
    reserved: u63 = 0,
};

pub const FreePhysicalRegion = struct {
    descriptor: PhysicalMemoryRegion,
    previous: ?*FreePhysicalRegion = null,
    next: ?*FreePhysicalRegion = null,
};

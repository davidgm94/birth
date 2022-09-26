const PhysicalAddressSpace = @This();

const common = @import("common");
const RNU = @import("RNU");
const PhysicalMemoryRegion = RNU.PhysicalMemoryRegion;
const Spinlock = RNU.Spinlock;

const log = common.log.scoped(.PhysicalAddressSpace);

zero_free_list: List = .{},
free_list: List = .{},
lock: Spinlock = .{},

pub fn allocate_pages(physical_address_space: *PhysicalAddressSpace, comptime page_size: u64, page_count: u64, flags: Flags) ?PhysicalMemoryRegion {
    physical_address_space.lock.acquire();
    defer physical_address_space.lock.release();

    var list = if (flags.zeroed) &physical_address_space.zero_free_list else &physical_address_space.free_list;
    var node_ptr = list.first;
    const size = page_size * page_count;

    const allocated_region = blk: {
        while (node_ptr) |node| : (node_ptr = node.next) {
            if (node.descriptor.size > size) {
                const allocated_region = PhysicalMemoryRegion{
                    .address = node.descriptor.address,
                    .size = size,
                };
                node.descriptor.address.value += size;
                node.descriptor.size -= size;

                break :blk allocated_region;
            } else if (node.descriptor.size == size) {
                const allocated_region = node.descriptor;
                if (node.previous) |previous| previous.next = node.next;
                if (node.next) |next| next.previous = node.previous;
                if (node_ptr == list.first) list.first = node.next;
                if (node_ptr == list.last) list.last = node.previous;

                break :blk allocated_region;
            }
        }

        return null;
    };

    // For now, just zero it out.
    // TODO: in the future, better organization of physical memory to know for sure if the memory still obbeys zero flag
    if (flags.zeroed) {
        const region_bytes = allocated_region.to_higher_half_virtual_address().access_bytes();
        common.zero(region_bytes);
    }

    return allocated_region;
}

pub fn free_pages(physical_address_space: *PhysicalAddressSpace, comptime page_size: u64, page_count: u64, flags: Flags) void {
    physical_address_space.lock.acquire();
    defer physical_address_space.lock.release();
    _ = page_size;
    _ = page_count;
    _ = flags;

    @panic("todo free pages");
}

pub fn log_free_memory(physical_address_space: *PhysicalAddressSpace) void {
    var node_ptr = physical_address_space.zero_free_list.first;
    var size: u64 = 0;
    while (node_ptr) |node| : (node_ptr = node.next) {
        size += node.descriptor.size;
    }

    log.debug("Free memory: {} bytes", .{size});
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

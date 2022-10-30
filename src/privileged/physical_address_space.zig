const PhysicalAddressSpace = @This();

const common = @import("common");
const assert = common.assert;
const log = common.log.scoped(.PhysicalAddressSpace);

const privileged = @import("privileged");
const PhysicalMemoryRegion = privileged.PhysicalMemoryRegion;

const arch = @import("arch");

free_list: List = .{},

const AllocateError = error{
    not_base_page_aligned,
    out_of_memory,
};

pub fn allocate(physical_address_space: *PhysicalAddressSpace, size: u64, page_size: u64) AllocateError!PhysicalMemoryRegion {
    log.debug("Trying to allocate {} bytes of physical memory", .{size});
    if (!common.is_aligned(size, arch.valid_page_sizes[0])) return AllocateError.not_base_page_aligned;

    var node_ptr = physical_address_space.free_list.first;

    const allocated_region = blk: {
        while (node_ptr) |node| : (node_ptr = node.next) {
            const result_address = node.descriptor.address.aligned_forward(page_size);
            const size_up = size + result_address.value - node.descriptor.address.value;
            if (node.descriptor.size > size_up) {
                const allocated_region = PhysicalMemoryRegion{
                    .address = result_address,
                    .size = size,
                };
                node.descriptor.address.value += size_up;
                node.descriptor.size -= size_up;

                break :blk allocated_region;
            } else if (node.descriptor.size == size_up) {
                const allocated_region = node.descriptor.offset(size_up - size);
                if (node.previous) |previous| previous.next = node.next;
                if (node.next) |next| next.previous = node.previous;
                if (node_ptr == physical_address_space.free_list.first) physical_address_space.free_list.first = node.next;
                if (node_ptr == physical_address_space.free_list.last) physical_address_space.free_list.last = node.previous;

                break :blk allocated_region;
            }
        }

        return AllocateError.out_of_memory;
    };

    // For now, just zero it out.
    // TODO: in the future, better organization of physical memory to know for sure if the memory still obbeys the upcoming zero flag
    //const region_bytes = allocated_region.to_higher_half_virtual_address().access_bytes();
    //common.zero(region_bytes);

    return allocated_region;
}

pub fn free(physical_address_space: *PhysicalAddressSpace, size: u64) void {
    _ = physical_address_space;
    _ = size;

    @panic("todo free pages");
}

pub fn log_free_memory(physical_address_space: *PhysicalAddressSpace) void {
    var node_ptr = physical_address_space.free_list.first;
    var size: u64 = 0;
    while (node_ptr) |node| : (node_ptr = node.next) {
        size += node.descriptor.size;
    }

    log.debug("Free memory: {} bytes", .{size});
}

const List = struct {
    first: ?*Region = null,
    last: ?*Region = null,
    count: u64 = 0,
};

pub const Region = struct {
    descriptor: PhysicalMemoryRegion,
    previous: ?*Region = null,
    next: ?*Region = null,
};

const common = @import("common");
const CustomAllocator = common.CustomAllocator;
const valid_page_sizes = common.arch.x86_64.valid_page_sizes;

const privileged = @import("privileged");
const PhysicalAddressSpace = privileged.PhysicalAddressSpace;

pub var core_id: u8 = 0;
pub var bootstrap_address_space = PhysicalAddressSpace{};

pub fn physical_allocate(allocator: *CustomAllocator, size: u64, alignment: u64) CustomAllocator.Error!CustomAllocator.Result {
    _ = allocator;
    // TODO: proper error
    if (!common.is_aligned(alignment, valid_page_sizes[0])) {
        return CustomAllocator.Error.OutOfMemory;
    }

    const result = bootstrap_address_space.allocate(size, valid_page_sizes[0]) catch return CustomAllocator.Error.OutOfMemory;

    return CustomAllocator.Result{
        .address = result.address.value(),
        .size = result.size,
    };
}

pub fn physical_resize(allocator: *CustomAllocator, old_memory: []u8, old_alignment: u29, new_size: usize) ?usize {
    _ = allocator;
    _ = old_memory;
    _ = old_alignment;
    _ = new_size;
    @panic("todo physical_resize");
}

pub fn physical_free(allocator: *CustomAllocator, memory: []u8, alignment: u29) void {
    _ = allocator;
    _ = memory;
    _ = alignment;
    @panic("todo physical_free");
}

pub var physical_allocator = CustomAllocator{
    .callback_allocate = physical_allocate,
    .callback_resize = physical_resize,
    .callback_free = physical_free,
};

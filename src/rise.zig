const lib = @import("lib");
const Allocator = lib.Allocator;
const valid_page_sizes = lib.arch.x86_64.valid_page_sizes;

const privileged = @import("privileged");
const Capabilities = privileged.Capabilities;
const CPU_stop = privileged.arch.CPU_stop;
const CTE = Capabilities.CTE;
const PhysicalAddress = privileged.PhysicalAddress;
const PhysicalAddressSpace = privileged.PhysicalAddressSpace;

pub export var core_id: u8 = 0;
pub var bootstrap_address_space = PhysicalAddressSpace{};

pub fn physical_allocate(allocator: *Allocator, size: u64, alignment: u64) Allocator.Allocate.Error!Allocator.Allocate.Result {
    _ = allocator;
    // TODO: proper error
    if (!lib.isAligned(alignment, valid_page_sizes[0])) {
        return Allocator.Allocate.Error.OutOfMemory;
    }

    const result = bootstrap_address_space.allocate(size, valid_page_sizes[0]) catch return Allocator.Allocate.Error.OutOfMemory;
    if (!lib.isAligned(alignment, valid_page_sizes[0])) {
        return Allocator.Allocate.Error.OutOfMemory;
    }

    return Allocator.Allocate.Result{
        .address = result.address.value(),
        .size = result.size,
    };
}

pub fn physical_resize(allocator: *Allocator, old_memory: []u8, old_alignment: u29, new_size: usize) ?usize {
    _ = allocator;
    _ = old_memory;
    _ = old_alignment;
    _ = new_size;
    @panic("todo physical_resize");
}

pub fn physical_free(allocator: *Allocator, memory: []u8, alignment: u29) void {
    _ = allocator;
    _ = memory;
    _ = alignment;
    @panic("todo physical_free");
}

pub var physical_allocator = Allocator{
    .callback_allocate = physical_allocate,
};

comptime {
    if (lib.os != .freestanding) @compileError("Kernel file included non-kernel project");
}

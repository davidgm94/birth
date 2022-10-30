const privileged = @import("privileged");
const PhysicalAddressSpace = privileged.PhysicalAddressSpace;
const VirtualAddress = privileged.VirtualAddress;

pub var bsp_allocator = Allocator{};
pub var bsp_address_space = PhysicalAddressSpace{};

pub const Allocator = struct {
    address: VirtualAddress = VirtualAddress.invalid(),
    allocated: u32 = 0,
    size: u32 = 0,

    pub const Error = error{
        out_of_memory,
    };

    pub fn allocate(allocator: *Allocator, size: usize, alignment: usize) Error!VirtualAddress {
        const aligned_address = allocator.address.offset(allocator.allocated).aligned_forward(alignment);
        const top_address = aligned_address.offset(size);
        if (top_address.value > allocator.address.offset(size).value) {
            return Error.out_of_memory;
        }

        allocator.allocated = @intCast(u32, top_address.value - allocator.address.value);

        return aligned_address;
    }
};

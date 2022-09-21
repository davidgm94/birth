const std = @import("../common/std.zig");
const Allocator = std.CustomAllocator;

pub const Buffer = struct {
    virtual_address: u64,
    total_size: u64,
    completed_size: u64,

    pub const WriteOption = enum {
        can_write,
        cannot_write,
    };

    pub const Initialization = struct {
        size: u64,
        alignment: u64,
    };

    pub fn new(allocator: Allocator, size: u64, alignment: u64) !Buffer {
        const result = try allocator.allocate_bytes(size, alignment);
        //const allocation_slice = try allocator.allocBytes(@intCast(u29, initialization.alignment), initialization.size, 0, 0);
        // INFO: this can never be zero since the allocator guarantees a valid address in RNU
        return Buffer{
            .virtual_address = result.address,
            .total_size = result.size,
            .completed_size = 0,
        };
    }
};

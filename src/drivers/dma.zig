const std = @import("std");
const Allocator = std.mem.Allocator;

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

    pub fn new(virtual_address: u64, size: u64) !Buffer {
        //const allocation_slice = try allocator.allocBytes(@intCast(u29, initialization.alignment), initialization.size, 0, 0);
        // INFO: this can never be zero since the allocator guarantees a valid address in RNU
        return Buffer{
            .address = virtual_address,
            .total_size = size,
            .completed_size = 0,
        };
    }
};

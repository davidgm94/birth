const kernel = @import("../../kernel.zig");
const TODO = kernel.TODO;
const virtio = @import("virtio.zig");

pub const Device = struct {
    queue: *virtio.Queue,
    address: u64,
    index: u16,
    ack_used_index: u16,
    read_only: bool,
};


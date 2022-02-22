const kernel = @import("kernel.zig");
pub const Information = struct
{
    terminal_callback: fn(msg: [*]const u8, msg_length: u64) callconv(.C) void,
    rsdp_address: u64,
    memory_map_entry_count: u64,
    memory_map_entries: [1024]kernel.MemoryRegion,
};
pub var info: Information = undefined;


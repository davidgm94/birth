const lib = @import("lib");

pub const GPT = @import("partition_table/gpt.zig");
pub const MBR = @import("partition_table/mbr.zig");

test {
    _ = GPT;
    _ = MBR;
}

pub const Type = lib.PartitionTableType;

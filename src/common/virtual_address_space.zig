const VirtualAddressSpace = @This();

const common = @import("../common.zig");
const TODO = common.TODO;
const Allocator = common.Allocator;
const arch = common.arch;

arch: arch.AddressSpace,
allocator: Allocator,

pub fn new() ?VirtualAddressSpace {
    TODO(@src());
}

pub fn from_context(context: anytype) VirtualAddressSpace {
    return VirtualAddressSpace{
        .arch = context,
        .allocator = undefined,
    };
}

pub fn from_current() ?VirtualAddressSpace {
    TODO(@src());
}

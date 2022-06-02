const VirtualAddress = @This();

value: u64,

pub inline fn new(value: u64) VirtualAddress {
    return VirtualAddress{
        .value = value,
    };
}

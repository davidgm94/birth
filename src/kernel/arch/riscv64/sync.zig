pub inline fn synchronize() void {
    asm volatile ("fence");
}

// Atomic test&set
pub inline fn lock_test_and_set(a: *usize, b: usize) usize {
    return @atomicRmw(usize, a, .Xchg, b, .Acquire);
}

// Lock release, set *a to 0
pub inline fn lock_release(a: *usize) void {
    asm volatile ("amoswap.w zero, zero, (%[arg])"
        :
        : [arg] "r" (a),
    );
}

pub inline fn set_hart_id(address: u64) void {
    asm volatile ("mv tp, %[address]"
        :
        : [address] "r" (address),
    );
}

pub inline fn get_hart_id() usize {
    return asm volatile ("mv %[result], tp"
        : [result] "=r" (-> usize),
    );
}

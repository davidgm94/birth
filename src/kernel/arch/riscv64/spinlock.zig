const kernel = @import("../../kernel.zig");
const arch = kernel.arch;

_lock: usize align(64),
hart: ?u64,

pub fn acquire(self: *@This()) void {
    if (self.is_locked()) {
        @panic("lock already held");
    } else {
        arch.disable_interrupts(); // disable interrupts to avoid deadlock
        while (arch.sync.lock_test_and_set(&self._lock, 1) == 0) {}
        arch.sync.synchronize();
        self.hart = arch.sync.hart_id(); // Set hart ID
    }
}

pub fn release(self: *@This()) void {
    if (self.is_locked()) {
        self.hart = null;
        arch.sync.synchronize();
        arch.sync.lock_release(&self._lock);
        arch.enable_interrupts();
    } else {
        @panic("not holding lock");
    }
}

pub inline fn is_locked(self: *const @This()) bool {
    if (self._lock == 1) {
        if (self.hart) |hart| {
            if (hart == arch.sync.hart_id()) return true;
        } else @panic("lock has no hart id");
    }

    return false;
}

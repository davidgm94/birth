//! Spinlock

const kernel = @import("../../kernel.zig");
const arch = kernel.arch;

// Spinlock Struct
_lock: usize align(64),
hart: i64,

/// Lock itself
pub fn lock(self: *@This()) void {
    if (self.holding()) {
        @panic("lock already held");
    } else {
        arch.disable_interrupts(); // disable interrupts to avoid deadlock
        while (arch.sync.lock_test_and_set(&self._lock, 1) == 0) {}
        arch.sync.synchronize();
        self.hart = @intCast(i64, arch.sync.hart_id()); // Set hart ID
    }
}

/// Release itself
pub fn unlock(self: *@This()) void {
    if (self.holding()) {
        self.hart = -1;
        arch.sync.synchronize();
        arch.sync.lock_release(&self._lock);
        arch.enable_interrupts();
    } else {
        @panic("not holding lock");
    }
}

// Check for holding
inline fn holding(self: *const @This()) bool {
    if (self._lock == 1 and self.hart == @intCast(i64, arch.sync.hart_id())) {
        return true;
    } else {
        return false;
    }
}

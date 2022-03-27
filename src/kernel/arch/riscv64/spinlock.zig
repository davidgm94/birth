//! Spinlock

const kernel = @import("../../kernel.zig");
const arch = kernel.arch;

// Spinlock Struct
pub const Spinlock = struct {
    _lock: usize align(64),
    hart: i64,

    /// Lock itself
    pub fn lock(self: *Spinlock) void {
        if (self.holding()) {
            @panic("lock already held");
        } else {
            arch.disable_interrupts(); // disable interrupts to avoid deadlock
            while (arch.__sync_lock_test_and_set(&self._lock, 1) == 0) {}
            arch.__sync_synchronize();
            self.hart = @intCast(i64, arch.hart_id()); // Set hart ID
        }
    }

    /// Release itself
    pub fn unlock(self: *Spinlock) void {
        if (self.holding()) {
            self.hart = -1;
            arch.__sync_synchronize();
            arch.__sync_lock_release(&self._lock);
            arch.enable_interrupts();
        } else {
            @panic("not holding lock");
        }
    }

    // Check for holding
    inline fn holding(self: *const Spinlock) bool {
        if (self._lock == 1 and self.hart == @intCast(i64, arch.hart_id())) {
            return true;
        } else {
            return false;
        }
    }
};

const std = @import("std");
const builtin = @import("builtin");
const current_arch = builtin.cpu.arch;
const arch = switch (current_arch) {
    .riscv64 => @import("arch/riscv64/riscv64.zig"),
    .x86_64 => @import("arch/x86_64.zig"),
    else => @compileError("CPU architecture not supported"),
};

/// Arch-specific part of the address space
pub const AddressSpace = arch.AddressSpace;
pub const Spinlock = arch.Spinlock;
pub const page_size = arch.page_size;
pub const page_shifter = @ctz(u64, page_size);

pub const enable_interrupts = arch.enable_interrupts;
pub const disable_interrupts = arch.disable_interrupts;
pub const are_interrupts_enabled = arch.are_interrupts_enabled;

pub const get_memory_map = arch.get_memory_map;

pub const Writer = struct {
    const Error = error{};
    pub var lock: arch.Spinlock = undefined;
    pub var should_lock = false;
    fn write(_: void, bytes: []const u8) Error!usize {
        if (should_lock) {
            lock.acquire();
        }
        defer {
            if (should_lock) {
                lock.release();
            }
        }

        return arch.writer_function(bytes);
    }
};

pub var writer = std.io.Writer(void, Writer.Error, Writer.write){ .context = {} };

pub fn check_page_size(asked_page_size: u64) u64 {
    for (arch.valid_page_sizes) |valid_page_size| {
        if (asked_page_size == valid_page_size) return asked_page_size;
    }

    unreachable;
}

pub const CPU = struct {
    lapic_id: u32,
    is_bootstrap: bool,
};

pub const bootstrap_stack_size = 0x10000;

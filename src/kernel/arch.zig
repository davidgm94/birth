const std = @import("std");
const builtin = @import("builtin");
const current_arch = builtin.cpu.arch;
const arch = switch (current_arch) {
    .riscv64 => @import("arch/riscv64/riscv64.zig"),
    .x86_64 => @import("arch/x86_64.zig"),
    else => @compileError("CPU architecture not supported"),
};

pub const page_size = arch.page_size;

pub const enable_interrupts = arch.interrupts.enable;
pub const disable_interrupts = arch.interrupts.disable;

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

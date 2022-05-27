// UART Driver
const std = @import("std");
const kernel = @import("../../kernel.zig");
const Spinlock = kernel.arch.Spinlock;

// the UART control registers.
// some have different meanings for
// read vs write.
// http://byterunner.com/16550.html

const RHR = 0; // receive holding register (for input bytes)
const THR = 0; // transmit holding register (for output bytes)
const IER = 1; // interrupt enable register
const FCR = 2; // FIFO control register
const ISR = 2; // interrupt status register
const LCR = 3; // line control register
const LSR = 5; // line status register

/// UART Driver
/// seems not thread-safe, use with caution when in SMP mode
pub fn UART(comptime base_address: u64) type {
    return struct {
        const ptr = @intToPtr([*c]volatile u8, base_address);

        /// Return an uninitialized Uart instance
        /// init set baud rate and enable UART
        /// We need this comptime parameter to avoid locking, which causes to enable interrupts
        pub fn init(self: *@This(), comptime lock: bool) void {
            if (lock) self.lock.acquire();
            defer if (lock) self.lock.release();

            // Volatile needed
            // using C-type ptr

            // Disable interrupt
            ptr[IER] = 0x00;

            // Enter setting mode
            ptr[LCR] = 0x80;
            // Set baud rate to 38.4K, other value may be valid
            // but here just copy xv6 behaviour
            ptr[0] = 0x03;
            ptr[1] = 0x00;
            // Leave setting mode
            ptr[LCR] = 0x03;

            // Reset and enable FIFO
            ptr[FCR] = 0x07;

            // Re-enable interrupt
            ptr[IER] = 0x01;
        }

        pub inline fn raw_read() ?u8 {
            if (ptr[5] & 1 == 0) return null else return ptr[0];
        }

        pub inline fn raw_write(byte: u8) void {
            // Wait until previous data is flushed
            while (ptr[5] & (1 << 5) == 0) {}

            // Write our data
            ptr[0] = byte;
        }

        /// Get a char from UART
        /// Return a optional u8, must check
        pub fn get(self: *@This()) ?u8 {
            self.lock.acquire();
            defer self.lock.release();
            const result = raw_read();
            return result;
        }

        pub fn write_bytes(self: *@This(), bytes: []const u8, comptime lock: bool) void {
            if (lock) self.lock.acquire();
            defer if (lock) self.lock.release();
            for (bytes) |byte| {
                raw_write(byte);
            }
        }

        pub fn handle_interrupt(self: *@This()) void {
            if (self.get()) |byte| {
                switch (byte) {
                    8 => {
                        kernel.arch.writer.print("{} {}", .{ byte, byte }) catch unreachable;
                    },
                    else => kernel.arch.writer.print("{c}", .{byte}),
                }
            }
        }
    };
}

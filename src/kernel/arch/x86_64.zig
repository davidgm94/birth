const kernel = @import("../kernel.zig");
const TODO = kernel.TODO;

const log = kernel.log.scoped(.x86_64);

const Stivale2 = @import("x86_64/limine/stivale2/stivale2.zig");

pub const page_size = 0x1000;
pub const Spinlock = @import("x86_64/spinlock.zig");

// TODO
pub inline fn enable_interrupts() void {}
pub inline fn disable_interrupts() void {}

pub export fn start(stivale_struct: *Stivale2.Struct) noreturn {
    log.debug("Hello kernel!", .{});
    const memory_map_struct = Stivale2.find(Stivale2.Struct.MemoryMap, stivale_struct) orelse @panic("Stivale had no memory map struct");
    const memory_map = Stivale2.process_memory_map(memory_map_struct);
    for (memory_map) |map_entry| {
        log.debug("(0x{x}, {}, {})", .{ map_entry.region.address, map_entry.region.size, map_entry.type });
    }

    while (true) {
        kernel.spinloop_hint();
    }
}

const IOPort = struct {
    const DMA1 = 0x0000;
    const PIC1 = 0x0020;
    const Cyrix_MSR = 0x0022;
    const PIT = 0x0040;
    const PS2 = 0x0060;
    const CMOS_RTC = 0x0070;
    const DMA_page_registers = 0x0080;
    const A20 = 0x0092;
    const PIC2 = 0x00a0;
    const DMA2 = 0x00c0;
    const E9_hack = 0x00e9;
    const ATA2 = 0x0170;
    const ATA1 = 0x01f0;
    const parallel_port = 0x0278;
    const serial2 = 0x02f8;
    const IBM_VGA = 0x03b0;
    const floppy = 0x03f0;
    const serial1 = 0x03f8;
};

const Serial = struct {
    const io_ports = [8]u16{
        0x3F8,
        0x2F8,
        0x3E8,
        0x2E8,
        0x5F8,
        0x4F8,
        0x5E8,
        0x4E8,
    };

    var initialization_state = [1]bool{false} ** 8;

    const InitError = error{
        already_initialized,
        not_present,
    };

    fn Port(comptime port_number: u8) type {
        comptime kernel.assert_unsafe(@src(), port_number > 0 and port_number <= 8);
        const port_index = port_number - 1;

        return struct {
            const io_port = io_ports[port_index];

            fn init() Serial.InitError!void {
                if (initialization_state[port_index]) return Serial.InitError.already_initialized;

                out8(io_port + 7, 0);
                if (in8(io_port + 7) != 0) return Serial.InitError.not_present;
                out8(io_port + 7, 0xff);
                if (in8(io_port + 7) != 0xff) return Serial.InitError.not_present;
                TODO();
            }
        };
    }
};

inline fn out8(comptime port: u16, value: u8) void {
    asm volatile ("outb %[value], %[port]"
        :
        : [value] "{al}" (value),
          [port] "N{dx}" (port),
    );
}

inline fn in8(comptime port: u16) u8 {
    return asm volatile ("inb %[port], %[result]"
        : [result] "={al}" (-> u8),
        : [port] "N{dx}" (port),
    );
}

pub inline fn writer_function(str: []const u8) usize {
    for (str) |c| {
        out8(IOPort.E9_hack, c);
    }

    return str.len;
}

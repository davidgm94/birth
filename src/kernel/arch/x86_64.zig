const kernel = @import("../kernel.zig");
const TODO = kernel.TODO;

const log = kernel.log.scoped(.x86_64);

const Stivale2 = @import("x86_64/limine/stivale2/stivale2.zig");

pub const page_size = 0x1000;
pub const Spinlock = @import("x86_64/spinlock.zig");

pub inline fn enable_interrupts() void {
    asm volatile ("sti");
}

pub inline fn disable_interrupts() void {
    asm volatile ("cli");
}

pub export fn start(stivale_struct: *Stivale2.Struct) noreturn {
    log.debug("Hello kernel!", .{});
    const memory_map_struct = Stivale2.find(Stivale2.Struct.MemoryMap, stivale_struct) orelse @panic("Stivale had no memory map struct");
    const rsdp_struct = Stivale2.find(Stivale2.Struct.RSDP, stivale_struct) orelse @panic("Stivale had no RSDP struct");
    const framebuffer_struct = Stivale2.find(Stivale2.Struct.Framebuffer, stivale_struct) orelse @panic("Stivale had no framebuffer struct");
    const kernel_struct = Stivale2.find(Stivale2.Struct.KernelFileV2, stivale_struct) orelse @panic("Stivale had no kernel struct");
    const modules_struct = Stivale2.find(Stivale2.Struct.Modules, stivale_struct) orelse @panic("Stivale had no modules struct");
    const epoch_struct = Stivale2.find(Stivale2.Struct.Epoch, stivale_struct) orelse @panic("Stivale had no epoch struct");
    _ = rsdp_struct;
    _ = framebuffer_struct;
    _ = kernel_struct;
    _ = modules_struct;
    _ = epoch_struct;

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

pub const rax = SimpleR64("rax");
pub const rbx = SimpleR64("rbx");
pub const rcx = SimpleR64("rcx");
pub const rdx = SimpleR64("rdx");
pub const rbp = SimpleR64("rbp");
pub const rsp = SimpleR64("rsp");
pub const rsi = SimpleR64("rsi");
pub const rdi = SimpleR64("rdi");
pub const r8 = SimpleR64("r8");
pub const r9 = SimpleR64("r9");
pub const r10 = SimpleR64("r10");
pub const r11 = SimpleR64("r11");
pub const r12 = SimpleR64("r12");
pub const r13 = SimpleR64("r13");
pub const r14 = SimpleR64("r14");
pub const r15 = SimpleR64("r15");

pub fn SimpleR64(comptime name: []const u8) type {
    return struct {
        pub inline fn read() u64 {
            return asm volatile ("mov %%" ++ name ++ ", %[result]"
                : [result] "={rax}" (-> u64),
            );
        }

        pub inline fn write(value: u64) void {
            asm volatile ("mov %[in], %%" ++ name
                :
                : [in] "r" (value),
            );
        }
    };
}

pub fn ComplexR64(comptime name: []const u8, comptime BitEnum: type) type {
    return struct {
        pub inline fn read_raw() u64 {
            return asm volatile ("mov %%" ++ name ++ ", %[result]"
                : [result] "={rax}" (-> u64),
            );
        }

        pub inline fn write_raw(value: u64) void {
            asm volatile ("mov %[in], %%" ++ name
                :
                : [in] "r" (value),
            );
        }

        pub inline fn read() u64 {
            return Value{
                .value = read_raw(),
            };
        }

        pub inline fn write(value: Value) void {
            write_raw(value.value);
        }

        pub inline fn get_bit(comptime bit: BitEnum) bool {
            return read().get_bit(bit);
        }

        pub inline fn set_bit(comptime bit: BitEnum) void {
            var value = read();
            value.set_bit(bit);
            write(value);
        }

        pub inline fn clear_bit(comptime bit: BitEnum) void {
            var value = read();
            value.clear_bit(bit);
            write(value);
        }

        pub const Value = struct {
            value: u64,

            pub inline fn get_bit(value: Value, comptime bit: BitEnum) bool {
                return value.value & (1 << @enumToInt(bit)) != 0;
            }

            pub inline fn set_bit(value: *Value, comptime bit: BitEnum) void {
                value.value |= 1 << @enumToInt(bit);
            }

            pub inline fn clear_bit(value: *Value, comptime bit: BitEnum) void {
                const mask = ~(1 << @enumToInt(bit));
                value.value &= mask;
            }
        };
    };
}

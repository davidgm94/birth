const std = @import("std");
pub const page_size = 0x1000;
pub const Spinlock = @import("riscv64/spinlock.zig");
pub const sync = @import("riscv64/sync.zig");
pub const DeviceTree = @import("riscv64/device_tree.zig");
pub const max_cpu = 64;

const UART = @import("riscv64/uart.zig").UART;
var device_tree_address: u64 = 0;
const assert = std.debug.assert;

export fn init(boot_hart_id: u64, fdt_address: u64) callconv(.C) noreturn {
    init_logger();
    writer.lockless.print("Hello RNU. Boot HART id: {}. Device tree address: 0x{x}\n", .{boot_hart_id, fdt_address}) catch unreachable;
    const result = DeviceTree.parse(fdt_address);
    _ = result;
    spinloop();
}


const Context = struct {
    integer: [32]u64,
    pc: u64,
    interrupt_stack: u64,
    float: [32]u64,
    hart_id: u64,
};

pub const LocalStorage = struct {
    context: Context,
    padding: [page_size - @sizeOf(Context)]u8,

    comptime {
        std.debug.assert(@sizeOf(LocalStorage) == page_size);
    }
};

var local_storage: [max_cpu]LocalStorage = undefined;


export fn kernel_interrupt_handler() callconv(.C) noreturn {
    spinloop();
}

pub fn spinloop() noreturn {
    while (true) {}
}

const UART0 = 0x1000_0000;
pub var uart = UART(UART0){
    .lock = Spinlock{
        ._lock = 0,
        .hart = -1,
    },
};

pub fn init_logger() void {
    uart.init(false);
    _ = writer.lockless.write("Hello RNU\n") catch unreachable;
}

fn CSR(comptime reg_name: []const u8, comptime BitT: type) type {
    return struct {
        pub const Bit = BitT;
        pub inline fn write(value: u64) void {
            asm volatile ("csrw " ++ reg_name ++ ", %[arg1]"
                :
                : [arg1] "r" (value),
            );
        }

        pub inline fn read() u64 {
            return asm volatile ("csrr %[ret], " ++ reg_name
                : [ret] "=r" (-> usize),
            );
        }

        pub inline fn set(comptime bit: Bit) void {
            const value: u64 = 1 << @enumToInt(bit);
            asm volatile ("csrs " ++ reg_name ++ ", %[arg1]"
                :
                : [arg1] "r" (value),
            );
        }

        pub inline fn clear(comptime bit: Bit) void {
            const value: u64 = 1 << @enumToInt(bit);
            asm volatile ("csrc " ++ reg_name ++ ", %[arg1]"
                :
                : [arg1] "r" (value),
            );
        }
    };
}

const sstatus = CSR("sstatus", enum(u32) {
    SIE = 1,
    SPIE = 5,
    UBE = 6,
    SPP = 8,
});
const sie = CSR("sie", enum(u32) {
    SSIE = 1,
    STIE = 5,
    SEIE = 9,
});
const cycle = CSR("cycle", enum(u32) { foo = 0 });
const stvec = CSR("stvec", enum(u32) { foo = 0 });
const SATP = CSR("satp", enum(u32) { foo = 0 });

pub fn enable_interrupts() void {
    sstatus.set(.SIE);
}

// disable interrupt
pub fn disable_interrupts() void {
    sstatus.clear(.SIE);
}

const Writer = struct {
    const Error = error{};
    locked: Locked,
    lockless: Lockless,

    const Locked = std.io.Writer(void, Error, locked_write);
    const Lockless = std.io.Writer(void, Error, lockless_write);

    fn locked_write(_: void, bytes: []const u8) Error!usize {
        uart.write_bytes(bytes, true);
        return bytes.len;
    }

    fn lockless_write(_: void, bytes: []const u8) Error!usize {
        uart.write_bytes(bytes, false);
        return bytes.len;
    }
};

pub const writer = Writer{
    .locked = Writer.Locked{ .context = {} },
    .lockless = Writer.Lockless{ .context = {} },
};

pub const Bounds = struct {
    extern const kernel_start: u8;
    extern const kernel_end: u8;

    pub inline fn get_start() u64 {
        return @ptrToInt(&kernel_start);
    }

    pub inline fn get_end() u64 {
        return @ptrToInt(&kernel_end);
    }
};

const kernel = @import("../kernel.zig");
pub const Spinlock = @import("riscv64/spinlock.zig");
pub const sync = @import("riscv64/sync.zig");
pub const DeviceTree = @import("riscv64/device_tree.zig");
pub const Timer = @import("riscv64/timer.zig");
pub const Paging = @import("riscv64/paging.zig");
pub const Physical = @import("riscv64/physical.zig");
pub const Virtual = @import("riscv64/virtual.zig");
pub const Interrupts = @import("riscv64/interrupts.zig");
pub const SBI = @import("riscv64/opensbi.zig");
pub const virtio = @import("riscv64/virtio_common.zig");

pub const page_size = 0x1000;
pub const sector_size = 0x200;
pub const max_cpu = 64;
pub const dt_read_int = kernel.read_int_big;
pub var cpu_count: u64 = 0;
pub var current_cpu: u64 = 0;

const log = kernel.log.scoped(.RISCV64);

const TODO = kernel.TODO;

const UART = @import("riscv64/uart.zig").UART;

const file_size = 5312;
var file_buffer: [kernel.align_forward(file_size, sector_size)]u8 align(kernel.arch.page_size) = undefined;

fn read_disk_raw(buffer: []u8, start_sector: u64, sector_count: u64) []u8 {
    const total_size = sector_count * sector_size;
    kernel.assert(@src(), buffer.len >= total_size);
    var bytes_asked: u64 = 0;
    var sector_i: u64 = start_sector;
    while (sector_i < sector_count) : ({
        sector_i += 1;
    }) {
        const sector_physical = kernel.arch.Virtual.AddressSpace.virtual_to_physical(@ptrToInt(&buffer[bytes_asked]));
        virtio.block.perform_block_operation(.read, sector_i, sector_physical);
        bytes_asked += sector_size;
        while (virtio.read != bytes_asked) {
            asm volatile ("" ::: "memory");
        }
    }

    kernel.assert(@src(), bytes_asked == virtio.read);

    const read_bytes = virtio.read;
    virtio.read = 0;
    log.debug("Block device read {} bytes", .{read_bytes});
    kernel.assert(@src(), sector_count * sector_size == read_bytes);

    return buffer[0..read_bytes];
}

export fn init(boot_hart_id: u64, fdt_address: u64) callconv(.C) noreturn {
    current_cpu = boot_hart_id;
    init_logger();
    log.debug("Hello RNU. Arch: {s}. Build mode: {s}. Boot HART id: {}. Device tree address: 0x{x}", .{ @tagName(kernel.current_arch), @tagName(kernel.build_mode), boot_hart_id, fdt_address });
    device_tree.base_address = fdt_address;
    device_tree.parse();
    init_cpu_count();
    Timer.init();
    const start = Timer.get_timestamp();
    Paging.init();
    Interrupts.init(boot_hart_id);
    local_storage[boot_hart_id].init(boot_hart_id, true);
    const time = Timer.get_time_from_timestamp(Timer.get_timestamp() - start);
    virtio.block.init(0x10008000);
    const file = read_disk_raw(&file_buffer, 0, kernel.bytes_to_sector(file_size));
    _ = file;

    log.debug("Initialized in {} s {} us", .{ time.s, time.us });
    spinloop();
}

fn init_cpu_count() void {
    log.debug("CPU count initialized with 1. Is it correct?", .{});
    // TODO: take from the device tree
    cpu_count = 1;
}

const Context = struct {
    integer: [32]u64,
    pc: u64,
    interrupt_stack: u64,
    float: [32]u64,
    hart_id: u64,
    pid: u64,
};

extern var stack_top: u64;
const hart_stack_size = 0x8000;

pub const LocalStorage = struct {
    context: Context,
    padding: [page_size - @sizeOf(Context)]u8,

    comptime {
        kernel.assert_unsafe(@sizeOf(LocalStorage) == page_size);
    }

    fn init(self: *@This(), hart_id: u64, boot_hart: bool) void {
        self.context.hart_id = hart_id;
        self.context.interrupt_stack = @ptrToInt(&stack_top) - hart_stack_size * hart_id;
        log.debug("Interrupt stack: 0x{x}", .{self.context.interrupt_stack});
        self.context.pid = 0xffff_ffff_ffff_ffff;

        sscratch.write(@ptrToInt(&self.context));

        var sstatus_value = sstatus.read();
        sstatus_value |= 1 << 18 | 1 << 1;
        if (!boot_hart) sstatus_value |= 1 << 8 | 1 << 5;
        sstatus.write(sstatus_value);

        sie.write(0x220);

        if (!boot_hart) {
            TODO(@src());
        }
        //SBI.set_timer(0);
    }
};

var local_storage: [max_cpu]LocalStorage = undefined;

pub const OldContext = struct {
    reg: [32]usize,
    sstatus: usize,
    sepc: usize,
};

const Scause = enum(u64) {
    instruction_address_misaligned = 0,
    instruction_access_fault = 1,
    illegal_instruction = 2,
    breakpoint = 3,
    load_address_misaligned = 4,
    load_access_fault = 5,
    store_address_misaligned = 6,
    store_access_fault = 7,
    environment_call_from_user_mode = 8,
    environment_call_from_supervisor_mode = 9,
    instruction_page_fault = 12,
    load_page_fault = 13,
    store_page_fault = 15,

    supervisor_software_interrupt = 0x8000_0000_0000_0001,
    supervisor_timer_interrupt = 0x8000_0000_0000_0005,
    supervisor_external_interrupt = 0x8000_0000_0000_0009,
};

const ilog = kernel.log.scoped(.Interrupt);

export fn kernel_interrupt_handler(context: *OldContext, scause: Scause, stval: usize) void {
    disable_interrupts();
    Writer.should_lock = false;
    defer Writer.should_lock = true;

    _ = context;
    _ = stval;
    //ilog.debug("Interrupt. SCAUSE: {}. STVAL: 0x{x}", .{ scause, stval });
    const hart_id = local_storage[current_cpu].context.hart_id;
    switch (scause) {
        .supervisor_external_interrupt => Interrupts.handle_external_interrupt(hart_id),
        else => spinloop(),
    }

    enable_interrupts();
}

pub fn spinloop() noreturn {
    while (true) {}
}

pub const UART0 = 0x1000_0000;
pub var uart = UART(UART0){
    .lock = Spinlock{
        ._lock = 0,
        .hart = null,
    },
};

pub var device_tree: DeviceTree = undefined;

pub fn init_logger() void {
    uart.init(false);
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
pub const SATP = CSR("satp", enum(u32) { foo = 0 });
const sscratch = CSR("sscratch", enum(u32) { foo = 0 });

const SATP_SV39: usize = (8 << 60);
pub inline fn MAKE_SATP(pagetable: usize) usize {
    return (SATP_SV39 | (pagetable >> 12));
}

pub fn enable_interrupts() void {
    sstatus.set(.SIE);
}

// disable interrupt
pub fn disable_interrupts() void {
    sstatus.clear(.SIE);
}

pub const Writer = struct {
    const Error = error{};
    pub var should_lock = false;
    fn write(_: void, bytes: []const u8) Error!usize {
        if (should_lock) uart.write_bytes(bytes, true) else uart.write_bytes(bytes, false);
        return bytes.len;
    }
};

pub var writer = kernel.Writer(void, Writer.Error, Writer.write){ .context = {} };

pub inline fn print(comptime format: []const u8, args: anytype) void {
    writer.print(format, args) catch unreachable;
}

pub inline fn write(bytes: []const u8) void {
    _ = writer.write(bytes) catch unreachable;
}

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

pub const PTE_VALID: usize = (1 << 0);
pub const PTE_READ: usize = (1 << 1);
pub const PTE_WRITE: usize = (1 << 2);
pub const PTE_EXEC: usize = (1 << 3);
pub const PTE_USER: usize = (1 << 4);
pub const PTE_GLOBAL: usize = (1 << 5);
pub const PTE_ACCESSED: usize = (1 << 6);
pub const PTE_DIRTY: usize = (1 << 7);

pub const memory_layout = struct {
    pub const UART0: usize = 0x1000_0000;
};
pub inline fn flush_tlb() void {
    asm volatile ("sfence.vma zero, zero");
}
pub const PAGE_INDEX_MASK: usize = 0x1FF; // 9 bits
pub const PTE_FLAG_MASK: usize = 0x3FF; // 10 bits

pub inline fn PTE_FLAGS(pte: usize) usize {
    return pte & PTE_FLAG_MASK;
}

pub inline fn PAGE_INDEX(level: usize, virtual_address: usize) usize {
    const page_index = (virtual_address >> PAGE_INDEX_SHIFT(level)) & PAGE_INDEX_MASK;
    return page_index;
}

pub inline fn PTE_TO_PA(pte: usize) usize {
    const pa = (pte >> 10) << 12;
    return pa;
}

pub inline fn PA_TO_PTE(pa: usize) usize {
    const pte = (pa >> 12) << 10;
    return pte;
}
pub inline fn PAGE_INDEX_SHIFT(level: usize) u6 {
    return @intCast(u6, PAGE_SHIFT + 9 * level);
}
pub const PAGE_SHIFT: usize = 12;

pub fn get_context(hart_id: u64, machine: u64) u64 {
    return 2 * hart_id + machine;
}

pub const AddressSpace = struct {};

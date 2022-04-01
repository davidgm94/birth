// Builtin is available
const builtin = @import("builtin");
const kernel = @import("../kernel.zig");
const sbi = @import("riscv64/opensbi.zig");
pub const uart = @import("riscv64/uart.zig");
const device_tree = @import("riscv64/device_tree.zig");
pub const virtio = @import("riscv64/virtio.zig");
const PLIC = @import("riscv64/plic.zig");
pub const virtual = @import("riscv64/virtual.zig");
pub const physical = @import("riscv64/physical.zig");
pub const _spinlock = @import("riscv64/spinlock.zig");
pub const Spinlock = _spinlock.Spinlock;

const logger = std.log.scoped(.arch);

const std = @import("std");

/// Page size 4K
pub const page_size = 0x1000;

/// VM releated defines
/// bits offset within a page
pub const PAGE_SHIFT: usize = 12;

/// Page table entry masks
pub const PTE_VALID: usize = (1 << 0); // valid
pub const PTE_READ: usize = (1 << 1); // read permission
pub const PTE_WRITE: usize = (1 << 2); // write permission
pub const PTE_EXEC: usize = (1 << 3); // execute permission
pub const PTE_USER: usize = (1 << 4); // belongs to U mode

pub var memory_size: u64 = 0;
pub var memory_start: u64 = 0;
extern const kernel_end: usize;
extern const kernel_start: usize;

pub var device_tree_address: usize = 0;

/// Enable Interrupt
pub fn enable_interrupts() void {
    sstatus.set(.SIE);
}

// disable interrupt
pub fn disable_interrupts() void {
    sstatus.clear(.SIE);
}
pub fn get_start() u64 {
    return @ptrToInt(&kernel_start);
}
pub fn get_end() u64 {
    return @ptrToInt(&kernel_end);
}

pub inline fn PAGE_INDEX_SHIFT(level: usize) u6 {
    return @intCast(u6, PAGE_SHIFT + 9 * level);
}

pub const PAGE_INDEX_MASK: usize = 0x1FF; // 9 bits
pub const PTE_FLAG_MASK: usize = 0x3FF; // 10 bits

pub inline fn PTE_FLAGS(pte: usize) usize {
    return pte & PTE_FLAG_MASK;
}

pub inline fn PAGE_INDEX(level: usize, virtual_address: usize) usize {
    return (virtual_address >> PAGE_INDEX_SHIFT(level)) & PAGE_INDEX_MASK;
}

pub inline fn PTE_TO_PA(pte: usize) usize {
    return (pte >> 10) << 12;
}

pub inline fn PA_TO_PTE(pa: usize) usize {
    return (pa >> 12) << 10;
}

// SATP related
const SATP_SV39: usize = (8 << 60);
pub inline fn MAKE_SATP(pagetable: usize) usize {
    return (SATP_SV39 | (pagetable >> 12));
}

// HZ value
pub const HZ: usize = 100;

// MAGIC number indicates the cpu freq
pub const FREQ: usize = 1e7;

/// Memory layout
///
/// qemu -machine virt is set up like this,
/// based on qemu's hw/riscv/virt.c:
///
/// 00001000 -- boot ROM, provided by qemu
/// 02000000 -- CLINT
/// 0C000000 -- PLIC
/// 10000000 -- uart0
/// 10001000 -- virtio disk
/// 80000000 -- boot ROM jumps here in machine mode
///             -kernel loads the kernel here
/// unused RAM after 80000000.
///
/// the kernel uses physical memory thus:
/// 80200000 -- entry.S, then kernel text and data
/// end -- start of kernel page allocation area
/// PHYSTOP -- end RAM used by the kernel
const Memory_layout = struct {
    UART0: usize = 0x1000_0000,
    PLIC: usize = 0x0C00_0000,
};
pub const memory_layout = Memory_layout{};

pub inline fn __sync_synchronize() void {
    asm volatile ("fence");
}

// Atomic test&set
pub inline fn __sync_lock_test_and_set(a: *usize, b: usize) usize {
    return @atomicRmw(usize, a, .Xchg, b, .Acquire);
}

// Lock release, set *a to 0
pub inline fn __sync_lock_release(a: *usize) void {
    asm volatile ("amoswap.w zero, zero, (%[arg])"
        :
        : [arg] "r" (a),
    );
}

pub fn hart_id() usize {
    return asm volatile ("mv %[result], tp"
        : [result] "=r" (-> usize),
    );
}

pub fn get_time() usize {
    return asm volatile ("rdtime %[result]"
        : [result] "=r" (-> usize),
    );
}

pub fn get_cycle() usize {
    return asm volatile ("rdcycle %[result]"
        : [result] "=r" (-> usize),
    );
}

pub inline fn flush_tlb() void {
    asm volatile ("sfence.vma zero, zero");
}

pub fn init_logging() void {
    uart.uart.init();
}

pub inline fn spinloop() noreturn {
    while (true) {
        std.atomic.spinLoopHint();
    }
}

pub const Context = struct {
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

export fn zig_handler(context: *Context, scause: Scause, stval: usize) void {
    // disable interrupts
    // TODO: allow some interrupts when available
    disable_interrupts();

    // Handler dispatch
    switch (scause) {
        .breakpoint => {
            std.log.debug("Break point", .{});
            context.sepc += 2; // magic number to bypass ebreak itself, see https://rcore-os.github.io/rCore-Tutorial-deploy/docs/lab-1/guide/part-6.html
        },
        .supervisor_timer_interrupt => Clock.handle(),
        .supervisor_external_interrupt => PLIC.handle_interrupt(),
        else => {
            _ = scause;
            _ = context;
            _ = stval;
            //std.log.err("Interrupt scause: {s} (0x{x}), [sepc] = 0x{x:0>16}, [stval] = 0x{x:0>16}", .{ @tagName(scause), @enumToInt(scause), context.sepc, stval});
            @panic("Unhandled interrupt");
        },
    }

    // Re-enable interrupts
    enable_interrupts();
}

/// Setup 
pub fn init_interrupts() void {
    const int_ptr = @ptrToInt(asm_kernel_irq_vec);
    kernel.assert(@src(), int_ptr != 0);
    stvec.write(int_ptr);
    sie.set(.SEIE);
    sstatus.set(.SIE);
    const sie_value = sie.read();
    const sstatus_value = sstatus.read();
    logger.debug("SIE: 0x{x}, SSTATUS: 0x{x}", .{ sie_value, sstatus_value });
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

pub const Clock = struct {
    pub var TICK: u64 = 0;

    const SIE_STIE = 5;

    pub fn enable() void {
        sie.write(sie.read() | (1 << @enumToInt(sie.Bit.STIE)));
    }

    pub fn handle() void {
        TICK += 1;
        if (TICK % 100 == 0) {
            std.log.info("1s has been submitted to '长者' at tick {}", .{TICK});
        }
        sbi.set_timer(get_time() + (FREQ / HZ));
    }
};

const WriteError = error{};

const Writer = std.io.Writer(void, WriteError, write_bytes);
pub const writer = @as(Writer, .{ .context = {} });
fn write_bytes(_: void, bytes: []const u8) WriteError!usize {
    uart.uart.write_bytes(bytes);
    return bytes.len;
}

pub const set_timer = sbi.set_timer;

pub fn get_memory_map() void {
    const result = device_tree.parse(device_tree_address);
    std.debug.assert(result.memory_regions.len > 0);
    memory_start = result.memory_regions[0].address;
    for (result.memory_regions[0..result.memory_region_count]) |region| {
        memory_size += region.size;
    }
}

pub fn init_devices() void {
    const sstatus_value = sstatus.read();
    const sie_value = sie.read();
    logger.debug("SSTATUS: 0x{x}, SIE: 0x{x}", .{ sstatus_value, sie_value });
    virtio.init();
    if (virtio.gpu.address == 0) @panic("No GPU device found\n");
    if (virtio.block.address == 0) @panic("No block device found\n");
    virtio.gpu.init();
}

pub fn setup_external_interrupts() void {
    PLIC.init();
}

const file_size = 5312;
var file_buffer: [0x4000]u8 align(0x1000) = undefined;
pub fn read_file_test() void {
    logger.debug("Trying to read file", .{});
    const size = virtio.block.access(&file_buffer, @intCast(u32, kernel.align_forward(file_size, 512)), 0, .read, 0);
    logger.debug("Size: {}", .{size});
}

export fn init(boot_hart_id: usize, fdt_address: usize) noreturn {
    kernel.assert(@src(), hart_id() == boot_hart_id);
    device_tree_address = fdt_address;
    kernel.main();
}

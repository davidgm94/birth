const std = @import("std");
const assert = std.debug.assert;
const kernel = @import("../kernel.zig");
const interrupts = @import("x86_64/interrupts.zig");
const TODO = kernel.TODO;

pub const GS_base = MSR(0xc0000102);
pub const page_size = 0x1000;
pub const page_table_level_count = 4;

fn page_table_level_count_to_bit_map(level: u8) u8 {
    return switch (level) {
        4 => 48,
        5 => 57,
        else => @panic("invalid page table level count\n"),
    };
}

fn is_canonical_address(address: u64) bool {
    const sign_bit = address & (1 << 63) != 0;
    const significant_bit_count = page_table_level_count_to_bit_map(page_table_level_count);
    var i: u8 = 63;
    while (i >= significant_bit_count) : (i -= 1) {
        const bit = address & (1 << i) != 0;
        if (bit != sign_bit) return false;
    }

    return true;
}


var max_physical_address: u6 = 0;


/// Arch-specific part of kernel.LocalStorage
pub const LocalStorage = struct {
    id: u64,
};

pub var cpu_local_storages: [256]kernel.LocalStorage = undefined;


const Paging = struct {
    pat: PAT,
    cr3: u64,
    level_5_paging: bool,

    write_back_virtual_base: u64 = 0,
    write_cache_virtual_base: u64 = 0,
    uncacheable_virtual_base: u64 = 0,
    max_physical_address: u64 = 0,

    pub fn init(self: *@This()) void {
        kernel.log("Initializing paging...\n");
        defer kernel.log("Paging initialized\n");
        CR0.write(CR0.read() | (1 << @enumToInt(CR0.Bit.WP)));
        CR4.write(CR4.read() | (1 << @enumToInt(CR4.Bit.PCIDE)) | (1 << @enumToInt(CR4.Bit.SMEP)));
        EFER.write(EFER.read() | (1 << @enumToInt(EFER.Bit.NXE)) | (1 << @enumToInt(EFER.Bit.SCE)) | (1 << @enumToInt(EFER.Bit.TCE)));
        const pae = CR4.get_flag(.PAE);
        kernel.assert(pae, @src());
        max_physical_address = CPUID.get_max_physical_address();
        kernel.logf("Max physical addresss: {}\n", .{max_physical_address});
        self.pat = PAT.init();
        kernel.logf("{}\n", .{self.pat});
        self.cr3 = CR3.read();
        self.level_5_paging = false;

        if (!self.level_5_paging) {
            const base = 0xFFFF800000000000;
            self.write_back_virtual_base = base;
            self.write_cache_virtual_base = base;
            self.uncacheable_virtual_base = base;
            self.max_physical_address = 0x7F0000000000;
        } else {
            TODO();
        }

        {
            kernel.log("Consuming bootloader memory map...\n");
            defer kernel.log("Memory map consumed!\n");
            for (kernel.bootloader.info.memory_map_entries[0..kernel.bootloader.info.memory_map_entry_count]) |*entry| {
                var region_address = entry.address;
                var region_size = entry.size;

                outer: while (region_size != 0) {
                    for (kernel.PhysicalAllocator.reverse_sizes) |pmm_size, reverse_i| {
                        const i = kernel.PhysicalAllocator.sizes.len - reverse_i - 1;
                        if (region_size >= pmm_size and kernel.is_aligned(region_address, pmm_size)) {
                            kernel.PhysicalAllocator.free(region_address, i);
                            region_size -= pmm_size;
                            region_address += pmm_size;
                            continue :outer;
                        }
                    }

                    @panic("unreachable");
                }
            }
        }

        const last_entry = kernel.bootloader.info.memory_map_entries[kernel.bootloader.info.memory_map_entry_count - 1];
        const physical_high = kernel.align_forward(last_entry.address + last_entry.size, page_size);
        _ = physical_high;

        TODO();
    }

    pub fn make_page_table() !u64 {
        const page_table = try kernel.PhysicalAllocator.allocate_physical(page_size);
        std.mem.set(u8, @intToPtr([*]u8, page_table.get_writeback_virtual_address())[0..page_size], 0);
        return page_table;
    }

    const LevelType = u3;
    const PTE = struct {
        physical_address: PhysicalAddress,
        current_level: LevelType,
        context: *Paging,
    };
};

var paging: Paging = undefined;

pub inline fn spin() noreturn {
    asm volatile ("cli");
    while (true) {
        std.atomic.spinLoopHint();
    }
}

/// This sets the address of the CPU local storage
/// This is, when we do mov rax, qword ptr gs:x, we get this address + offset
pub fn set_cpu_local_storage(index: u64) void {
    GS_base.write(@ptrToInt(&cpu_local_storages[index]));
}

pub fn initialize_FPU() void {
    kernel.log("Initializing FPU...\n");
    defer kernel.log("FPU initialized\n");
    CR0.write(CR0.read() | (1 << @enumToInt(CR0.Bit.MP)) | (1 << @enumToInt(CR0.Bit.NE)));
    CR4.write(CR4.read() | (1 << @enumToInt(CR4.Bit.OSFXSR)) | (1 << @enumToInt(CR4.Bit.OSXMMEXCPT)));

    kernel.log("@TODO: MXCSR. See Intel manual\n");
    // @TODO: is this correct?
    const cw: u16 = 0x037a;
    asm volatile (
        \\fninit
        \\fldcw (%[cw])
        :
        : [cw] "r" (&cw),
    );
}

pub fn init_cache() void {
    kernel.log("Ensuring cache is initialized...\n");
    defer kernel.log("Cache initialized!\n");

    kernel.assert(!CR0.get_flag(.CD), @src());
    kernel.assert(!CR0.get_flag(.NW), @src());
}

pub fn init_interrupts() void {
    kernel.log("Initializing interrupts...\n");
    defer kernel.log("Interrupts initialized!\n");

    PIC.disable();
    interrupts.IDT.fill();
    const idtr = interrupts.IDT.Register{
        .address = &interrupts.IDT.table,
    };
    asm volatile (
        \\lidt (%[idt_address])
        :
        : [idt_address] "r" (&idtr),
    );
    kernel.log("@TODO: initialize interrupts\n");
    kernel.log("@TODO: load GDT since the segment selectors are wrong\n");
}


pub const PhysicalAddress = struct {
    value: u64,

    pub inline fn check(self: *const @This()) void {
        if (self.value > paging.max_physical_address) @panic("invalid physical address\n");
    }
    pub fn get_writeback_virtual_address(self: *const @This()) u64 {
        self.check();
        return paging.write_back_virtual_base + self.value;
    }
};

pub fn init() void {
    const foo = interrupts.IDT.table;
    _ = foo;
    set_cpu_local_storage(0);
    initialize_FPU();
    init_cache();
    init_interrupts();
    paging.init();
}

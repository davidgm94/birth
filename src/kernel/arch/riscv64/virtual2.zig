//! Memory management entry point

const kernel = @import("../../kernel.zig");
const arch = kernel.arch;
const physical = kernel.arch.physical;
const std = @import("std");

pub inline fn PAGE_ROUND_UP(ptr: usize) usize {
    return (ptr + arch.page_size - 1) & ~@as(usize, arch.page_size - 1);
}

pub inline fn PAGE_ROUND_DOWN(ptr: usize) usize {
    return ptr & ~@as(usize, arch.page_size - 1);
}

extern const kernel_end: usize;
extern const kernel_start: usize;

/// Global log for this file
const log = std.log.scoped(.memory);

/// MAXVA is the maximum address for virtual address space
/// SV39 mode, to avoid having to sign-extend virtual addresses
/// that have the high bit set.
const MAXVA: usize = (1 << (9 + 9 + 9 + 12 - 1));

const pagetable_t = [*]usize;
const pte_t = usize;

/// Init must be run after the device tree has been parsed.
pub fn init() void {

    // Security check
    if (arch.memory_size <= 4096) { // some magic number, memory should be way more then 4096 bytes
        @panic("Abnormal memory size, maybe the device tree hasn't been parsed yet'");
    }
    if (arch.memory_start == 0) { // memory start is not initialized
        @panic("Abnormal memory start, maybe the device tree hasn't been parsed yet'");
    }

    log.debug("Start building memory data structure", .{});

    // Calculate the start and end of the usable memory
    log.debug("Kernel end: 0x{x:0>16}", .{&kernel_end});
    const memory_start = PAGE_ROUND_UP(@ptrToInt(&kernel_end));
    const memory_end = PAGE_ROUND_DOWN(arch.device_tree_address);
    // const memory_end = PAGE_ROUND_DOWN(hwinfo.info.memory_start + hwinfo.info.memory_size);
    log.debug("Usable RAM start:\t 0x{x:0>16}", .{memory_start});
    log.debug("Usable RAM end:\t 0x{x:0>16}", .{memory_end});
    log.debug("Total usable RAM:\t {d}MiB", .{@intToFloat(f64, memory_end - memory_start) / 1024 / 1024});

    physical.init(memory_start, memory_end);

    log.info("Physical memory data structure initialized", .{});
}

/// Kernel pagetable before KPTI enabled
var kernel_init_pagetable: ?*usize = null; // use optional type

/// kernel_vm_init initialize the kernel_init_pagetable during initialization phase
pub fn kernel_vm_init() void {

    // Initialize the kernel pagetable
    const new_page = physical.alloc();
    if (new_page == null) {
        log.err("Failed to allocate kernel pagetable", .{});
        @panic("Out of memory");
    }
    kernel_init_pagetable = @intToPtr(*usize, new_page.?);
    @memset(@ptrCast([*]u8, kernel_init_pagetable.?), 0, arch.page_size);

    // Map UART
    directMap(
        @ptrCast([*]usize, kernel_init_pagetable.?),
        arch.memory_layout.UART0,
        arch.page_size,
        arch.PTE_READ | arch.PTE_WRITE,
        false,
    );

    // PLIC
    directMap(
        @ptrCast([*]usize, kernel_init_pagetable.?),
        arch.memory_layout.PLIC,
        0x40_0000,
        arch.PTE_READ | arch.PTE_WRITE,
        false,
    );

    const memory_start = PAGE_ROUND_UP(@ptrToInt(&kernel_end));
    const kernel_base = @ptrToInt(&kernel_start);

    // Map kernel image as read-only and executable
    directMap(
        @ptrCast([*]usize, kernel_init_pagetable.?),
        kernel_base,
        memory_start - kernel_base,
        arch.PTE_READ | arch.PTE_WRITE | arch.PTE_EXEC,
        false,
    );

    // Map all other usable physical memory
    directMap(
        @ptrCast([*]usize, kernel_init_pagetable.?),
        memory_start,
        arch.memory_size + arch.memory_start - memory_start,
        arch.PTE_READ | arch.PTE_WRITE,
        false,
    );
}

/// enable_paging setup paging for initialization-time paging
pub fn enablePaging() void {
    if (kernel_init_pagetable) |pagetable| {
        log.debug("Enabling paging for pagetable at 0x{x:0>16}", .{@ptrToInt(pagetable)});

        // Set CSR satp
        arch.SATP.write(arch.MAKE_SATP(@ptrToInt(pagetable)));

        // for safety
        arch.flush_tlb();
    } else {
        @panic("Kernel pagetable not initialized");
    }
}

/// directMap map the physical memory to virtual memory
/// the start and the end must be page start
fn directMap(pagetable: pagetable_t, start: usize, size: usize, permission: usize, allow_remap: bool) void {
    map_pages(pagetable, start, start, size, permission, allow_remap);
}

pub fn map(start: u64, size: u64) void {
    directMap(@ptrCast([*]usize, kernel_init_pagetable.?), start, size, arch.PTE_READ | arch.PTE_WRITE, false);
}

fn map_pages(pagetable: pagetable_t, virtual_addr: usize, physical_addr: usize, size: usize, permission: usize, allow_remap: bool) void {
    var virtual_page = PAGE_ROUND_DOWN(virtual_addr);
    var physical_page = physical_addr;
    const virtual_end = PAGE_ROUND_DOWN(virtual_addr + size - 1);

    // Security check for permission
    if (permission & ~(arch.PTE_FLAG_MASK) != 0) {
        log.err("Illegal permission, [permission] = {x:0>16}", .{permission});
        @panic("illegal permission");
    }

    while (virtual_page <= virtual_end) : ({
        virtual_page += arch.page_size;
        physical_page += arch.page_size;
    }) {
        const optional_pte = walk(pagetable, virtual_page, true);
        if (optional_pte) |pte| {

            // Existing entry
            if ((@intToPtr(*usize, pte).* & arch.PTE_VALID != 0) and !allow_remap) {
                log.err("mapping pages failed, [virtual_addr] = 0x{x:0>16}, [physical_addr] = 0x{x:0>16}, [size] = {d}", .{ virtual_page, physical_page, size });
                @panic("mapping pages failed");
            }

            // Map a physical to virtual page
            @intToPtr(*usize, pte).* = arch.PA_TO_PTE(physical_page) | permission | arch.PTE_VALID;
        } else {
            // Walk is going wrong somewhere
            log.err(
                \\mapping pages failed, 
                \\[virtual_addr] = 0x{x:0>16},
                \\[physical_addr] = 0x{x:0>16},
                \\[size] = {d}
            , .{ virtual_addr, physical_addr, size });
            @panic("mapping pages failed");
        }
    }
}

/// walk is used to find the corresponding physical address of certain virtual address
/// allocate a new page if required
fn walk(pagetable: pagetable_t, virtual_addr: usize, alloc: bool) ?pte_t {
    // Safety check
    if (virtual_addr >= MAXVA) {
        log.err("Virtual address overflow: [virtual_addr] = 0x{x:0>16}", .{virtual_addr});
        @panic("walk: virtual_addr overflow");
    }

    var level: usize = 2;
    var pg_iter: pagetable_t = pagetable;
    while (level > 0) : (level -= 1) {
        const index = arch.PAGE_INDEX(level, virtual_addr);
        if (index == 74) {
            log.debug("Index 74 for VA 0x{x}", .{virtual_addr});
        }
        const pte: *usize = &pg_iter[index];
        if (pte.* & arch.PTE_VALID != 0) {
            // Next level if valid
            pg_iter = @intToPtr([*]usize, arch.PTE_TO_PA(pte.*));
        } else {
            if (alloc) {
                // Allocate a new page if not valid and need to allocate
                const new_page = physical.alloc();
                if (new_page) |page| {
                    pg_iter = @intToPtr([*]usize, page);
                    @memset(@ptrCast([*]u8, pg_iter), 0, arch.page_size);
                    pte.* = arch.PA_TO_PTE(page) | arch.PTE_VALID;
                } else {
                    log.err("allocate pagetable physical memory failed", .{});
                    @panic("Out of memory");
                }
            } else {
                return null;
            }
        }
    }
    const index = arch.PAGE_INDEX(0, virtual_addr);
    if (index == 74) {
        log.debug("Index 74 for VA 0x{x}", .{virtual_addr});
    }
    return @ptrToInt(&pg_iter[index]);
}

/// translate_addr translate a virtual address to a physical address
pub fn translate_addr(pagetable: pagetable_t, virtual_addr: usize) ?usize {
    const optional_pte = walk(pagetable, virtual_addr, false);
    if (optional_pte) |pte| {
        return arch.PTE_TO_PA(@intToPtr(*usize, pte).*);
    } else return null;
}

/// vmprint print out the pagetable
/// for debug usage
pub fn vmprint(pagetable: pagetable_t) void {
    log.debug("page table 0x{x}", .{@ptrToInt(pagetable)});
    if (@ptrToInt(pagetable) == 0) {
        @panic("null pagetable");
    }
    const prefix = "|| || ||";

    vmprint_walk(pagetable, 0, prefix);
}

fn vmprint_walk(pagetable: pagetable_t, level: usize, prefix: []const u8) void {
    // SV39 512 entry per block
    var i: usize = 0;
    while (i < 512) : (i += 1) {
        const pte: pte_t = pagetable[i];
        if (pte & arch.PTE_VALID == 0) {
            continue;
        }
        log.debug("{s}{d}: pte 0x{x:0>16} pa 0x{x:0>16}", .{
            prefix[0 .. level * 3],
            i,
            pte,
            arch.PTE_TO_PA(pte),
        });
        if (pte & (arch.PTE_READ | arch.PTE_WRITE | arch.PTE_EXEC) == 0) {
            // points to a lower-level page table
            const child = arch.PTE_TO_PA(pte);

            // Recurring
            vmprint_walk(@intToPtr([*]usize, child), level + 1, prefix);
        }
    }
}

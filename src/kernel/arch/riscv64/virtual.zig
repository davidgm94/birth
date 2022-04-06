const kernel = @import("../../kernel.zig");
const arch = kernel.arch;
const Physical = kernel.arch.Physical;
const page_size = kernel.arch.page_size;
/// Kernel pagetable before KPTI enabled
var kernel_init_pagetable: [*]usize = undefined; // use optional type

const early_print = kernel.arch.early_print;
const early_write = kernel.arch.early_write;
const pagetable_t = [*]usize;
const pte_t = usize;
const MAXVA: usize = (1 << (9 + 9 + 9 + 12 - 1));

const print = kernel.arch.early_print;
const write = kernel.arch.early_write;

fn page_round_up(address: u64) u64 {
    return kernel.align_forward(address, kernel.arch.page_size);
}

fn page_round_down(address: u64) u64 {
    return kernel.align_backward(address, kernel.arch.page_size);
}

/// kernel_vm_init initialize the kernel_init_pagetable during initialization phase
pub fn init() void {
    // Initialize the kernel pagetable
    const new_page = Physical.allocate(1, true) orelse @panic("Failed to allocate kernel pagetable. Out of memory");
    kernel_init_pagetable = @intToPtr([*]usize, new_page);

    write("mapping UART\n");
    // Map UART
    directMap(
        kernel_init_pagetable,
        arch.UART0,
        1,
        arch.PTE_READ | arch.PTE_WRITE,
        false,
    );

    write("mapping PLIC\n");
    // PLIC
    directMap(
        kernel_init_pagetable,
        arch.memory_layout.PLIC,
        64,
        arch.PTE_READ | arch.PTE_WRITE,
        false,
    );

    for (kernel.arch.Physical.reserved_regions) |region, i| {
        if (i == 1) {
            write("mapping kernel\n");
            // map kernel properly
            kernel.assert(@src(), kernel.arch.Physical.kernel_region.address == region.address);
            directMap(kernel_init_pagetable, kernel.arch.Physical.kernel_region.address, kernel.arch.Physical.kernel_region.page_count,
            // this can cause issues
            arch.PTE_READ | arch.PTE_EXEC | arch.PTE_WRITE, false);
        } else {
            print("mapping region {}\n", .{i});
            directMap(
                kernel_init_pagetable,
                region.address,
                region.page_count,
                // this can cause issues
                arch.PTE_READ,
                false,
            );
        }
    }

    for (kernel.arch.Physical.available_regions) |region| {
        directMap(
            kernel_init_pagetable,
            region.descriptor.address,
            region.descriptor.page_count,
            // this can cause issues
            arch.PTE_READ | arch.PTE_WRITE,
            false,
        );
    }

    enablePaging();
    write("enabled paging\n");
}

/// enable_paging setup paging for initialization-time paging
pub fn enablePaging() void {
    //logger.debug("Enabling paging for pagetable at 0x{x:0>16}", .{@ptrToInt(pagetable)});

    // Set CSR satp
    arch.SATP.write(arch.MAKE_SATP(@ptrToInt(kernel_init_pagetable)));

    // for safety
    arch.flush_tlb();
}

/// directMap map the physical memory to virtual memory
/// the start and the end must be page start
fn directMap(pagetable: pagetable_t, start: usize, page_count: usize, permission: usize, allow_remap: bool) void {
    map_pages(pagetable, start, start, page_count, permission, allow_remap);
}

pub fn map(start: u64, page_count: u64) void {
    directMap(kernel_init_pagetable, start, page_count, arch.PTE_READ | arch.PTE_WRITE, false);
}

fn map_pages(pagetable: pagetable_t, virtual_addr: usize, physical_addr: usize, page_count: usize, permission: usize, allow_remap: bool) void {
    kernel.assert(@src(), kernel.is_aligned(virtual_addr, page_size));
    kernel.assert(@src(), kernel.is_aligned(physical_addr, page_size));

    // Security check for permission
    if (permission & ~(arch.PTE_FLAG_MASK) != 0) {
        // logger.err("Illegal permission, [permission] = {x:0>16}", .{permission});
        @panic("illegal permission");
    }

    var page_i: u64 = 0;
    var virtual_page = virtual_addr;
    var physical_page = physical_addr;

    while (page_i < page_count) : ({
        virtual_page += arch.page_size;
        physical_page += arch.page_size;
        page_i += 1;
    }) {
        const optional_pte = walk(pagetable, virtual_page, true);
        if (optional_pte) |pte| {

            // Existing entry
            if ((@intToPtr(*usize, pte).* & arch.PTE_VALID != 0) and !allow_remap) {
                //logger.err("mapping pages failed, [virtual_addr] = 0x{x:0>16}, [physical_addr] = 0x{x:0>16}, [size] = {d}", .{ virtual_page, physical_page, size });
                @panic("mapping pages failed");
            }

            // Map a physical to virtual page
            @intToPtr(*usize, pte).* = arch.PA_TO_PTE(physical_page) | permission | arch.PTE_VALID;
        } else {
            // Walk is going wrong somewhere
            @panic("mapping pages failed");
        }
    }
}

/// walk is used to find the corresponding physical address of certain virtual address
/// allocate a new page if required
fn walk(pagetable: pagetable_t, virtual_addr: usize, alloc: bool) ?pte_t {
    // Safety check
    if (virtual_addr >= MAXVA) {
        //logger.err("Virtual address overflow: [virtual_addr] = 0x{x:0>16}", .{virtual_addr});
        @panic("walk: virtual_addr overflow");
    }

    var level: usize = 2;
    var pg_iter: pagetable_t = pagetable;
    while (level > 0) : (level -= 1) {
        const pte: *usize = &pg_iter[arch.PAGE_INDEX(level, virtual_addr)];
        if (pte.* & arch.PTE_VALID != 0) {
            // Next level if valid
            pg_iter = @intToPtr([*]usize, arch.PTE_TO_PA(pte.*));
        } else {
            if (alloc) {
                // Allocate a new page if not valid and need to allocate
                if (Physical.allocate(1, true)) |page| {
                    pg_iter = @intToPtr([*]usize, page);
                    pte.* = arch.PA_TO_PTE(page) | arch.PTE_VALID;
                } else {
                    //logger.err("allocate pagetable physical memory failed", .{});
                    @panic("Out of memory");
                }
            } else {
                return null;
            }
        }
    }
    return @ptrToInt(&pg_iter[arch.PAGE_INDEX(0, virtual_addr)]);
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
    //logger.debug("page table 0x{x}", .{@ptrToInt(pagetable)});
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
        //logger.debug("{s}{d}: pte 0x{x:0>16} pa 0x{x:0>16}", .{
        //prefix[0 .. level * 3],
        //i,
        //pte,
        //arch.PTE_TO_PA(pte),
        //});
        if (pte & (arch.PTE_READ | arch.PTE_WRITE | arch.PTE_EXEC) == 0) {
            // points to a lower-level page table
            const child = arch.PTE_TO_PA(pte);

            // Recurring
            vmprint_walk(@intToPtr([*]usize, child), level + 1, prefix);
        }
    }
}

// Paging behavior is controlled by the following control bits:
// • The WP and PG flags in control register CR0 (bit 16 and bit 31, respectively).
// • The PSE, PAE, PGE, LA57, PCIDE, SMEP, SMAP, PKE, CET, and PKS flags in control register CR4 (bit 4, bit 5, bit 7, bit 12, bit 17, bit 20, bit 21, bit 22, bit 23, and bit 24, respectively).
// • The LME and NXE flags in the IA32_EFER MSR (bit 8 and bit 11, respectively).
// • The AC flag in the EFLAGS register (bit 18).
// • The “enable HLAT” VM-execution control (tertiary processor-based VM-execution control bit 1; see Section 24.6.2, “Processor-Based VM-Execution Controls,” in the Intel® 64 and IA-32 Architectures Software Developer’s Manual, Volume 3C).

const kernel = @import("../../kernel.zig");
const x86_64 = @import("../x86_64.zig");
const TODO = kernel.TODO;
const log = kernel.log.scoped(.Paging_x86_64);
pub fn init() void {
    const max_pa = x86_64.CPUID.get_max_physical_address();
    log.debug("Max physical address: {}", .{max_pa});
    const pml4e = kernel.PhysicalMemory.allocate_assuming_identity_mapping([512]PML4E) orelse @panic("unable to allocate memory for PML4E");
    log.debug("PMLE: {any}", .{pml4e});
}

const PML4E = struct {
    value: Flags,

    const Flags = kernel.Bitflag(true, enum(u64) {
        present = 0,
        read_write = 1,
        user = 2,
        page_level_write_through = 3,
        page_level_cache_disable = 4,
        accessed = 5,
        hlat_restart = 11,
        execute_disable = 63, // IA32_EFER.NXE must be 1
    });
};

const PDPTE = struct {
    value: Flags,

    const Flags = kernel.Bitflag(true, enum(u64) {
        present = 0,
        read_write = 1,
        user = 2,
        page_level_write_through = 3,
        page_level_cache_disable = 4,
        accessed = 5,
        page_size = 7, // must be 0
        hlat_restart = 11,
        execute_disable = 63, // IA32_EFER.NXE must be 1
    });
};

const PDE = struct {
    value: Flags,

    const Flags = kernel.Bitflag(true, enum(u64) {
        present = 0,
        read_write = 1,
        user = 2,
        page_level_write_through = 3,
        page_level_cache_disable = 4,
        accessed = 5,
        page_size = 7, // must be 0
        hlat_restart = 11,
        execute_disable = 63, // IA32_EFER.NXE must be 1
    });
};

const PTE = struct {
    value: Flags,

    const Flags = kernel.Bitflag(true, enum(u64) {
        present = 0,
        read_write = 1,
        user = 2,
        page_level_write_through = 3,
        page_level_cache_disable = 4,
        accessed = 5,
        dirty = 6,
        pat = 7, // must be 0
        global = 8,
        hlat_restart = 11,
        // TODO: protection key
        execute_disable = 63, // IA32_EFER.NXE must be 1
    });
};

//const Paging = struct {
//pat: PAT,
//cr3: u64,
//level_5_paging: bool,

//write_back_virtual_base: u64 = 0,
//write_cache_virtual_base: u64 = 0,
//uncacheable_virtual_base: u64 = 0,
//max_physical_address: u64 = 0,

//pub fn init(self: *@This()) void {
//kernel.log("Initializing paging...\n");
//defer kernel.log("Paging initialized\n");
//CR0.write(CR0.read() | (1 << @enumToInt(CR0.Bit.WP)));
//CR4.write(CR4.read() | (1 << @enumToInt(CR4.Bit.PCIDE)) | (1 << @enumToInt(CR4.Bit.SMEP)));
//EFER.write(EFER.read() | (1 << @enumToInt(EFER.Bit.NXE)) | (1 << @enumToInt(EFER.Bit.SCE)) | (1 << @enumToInt(EFER.Bit.TCE)));
//const pae = CR4.get_flag(.PAE);
//kernel.assert(pae, @src());
//max_physical_address = CPUID.get_max_physical_address();
//kernel.logf("Max physical addresss: {}\n", .{max_physical_address});
//self.pat = PAT.init();
//kernel.logf("{}\n", .{self.pat});
//self.cr3 = CR3.read();
//self.level_5_paging = false;

//if (!self.level_5_paging) {
//const base = 0xFFFF800000000000;
//self.write_back_virtual_base = base;
//self.write_cache_virtual_base = base;
//self.uncacheable_virtual_base = base;
//self.max_physical_address = 0x7F0000000000;
//} else {
//TODO();
//}

//{
//kernel.log("Consuming bootloader memory map...\n");
//defer kernel.log("Memory map consumed!\n");
//for (kernel.bootloader.info.memory_map_entries[0..kernel.bootloader.info.memory_map_entry_count]) |*entry| {
//var region_address = entry.address;
//var region_size = entry.size;

//outer: while (region_size != 0) {
//for (kernel.PhysicalAllocator.reverse_sizes) |pmm_size, reverse_i| {
//const i = kernel.PhysicalAllocator.sizes.len - reverse_i - 1;
//if (region_size >= pmm_size and kernel.is_aligned(region_address, pmm_size)) {
//kernel.PhysicalAllocator.free(region_address, i);
//region_size -= pmm_size;
//region_address += pmm_size;
//continue :outer;
//}
//}

//@panic("unreachable");
//}
//}
//}

//const last_entry = kernel.bootloader.info.memory_map_entries[kernel.bootloader.info.memory_map_entry_count - 1];
//const physical_high = kernel.align_forward(last_entry.address + last_entry.size, page_size);
//_ = physical_high;

//TODO();
//}

//pub fn make_page_table() !u64 {
//const page_table = try kernel.PhysicalAllocator.allocate_physical(page_size);
//std.mem.set(u8, @intToPtr([*]u8, page_table.get_writeback_virtual_address())[0..page_size], 0);
//return page_table;
//}

//const LevelType = u3;
//const PTE = struct {
//physical_address: PhysicalAddress,
//current_level: LevelType,
//context: *Paging,
//};
//};

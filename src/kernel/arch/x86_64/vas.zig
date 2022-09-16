const std = @import("../../../common/std.zig");

const common = @import("common.zig");
const crash = @import("../../crash.zig");
const kernel = @import("../../kernel.zig");
const PhysicalAddress = @import("../../physical_address.zig");
const PhysicalAddressSpace = @import("../../physical_address_space.zig");
const registers = @import("registers.zig");
const Timer = @import("../../timer.zig");
const VirtualAddress = @import("../../virtual_address.zig");
const VirtualAddressSpace = @import("../../virtual_address_space.zig");
const VirtualMemoryRegion = @import("../../virtual_memory_region.zig");
const x86_64 = @import("common.zig");

const cr3 = registers.cr3;
const log = std.log.scoped(.VAS);
const MapError = VirtualAddressSpace.MapError;
const page_size = common.page_size;
const TranslationResult = VirtualAddressSpace.TranslationResult;

pub const Specific = struct {
    cr3: cr3 = undefined,

    pub fn format(specific: Specific, comptime _: []const u8, _: std.InternalFormatOptions, writer: anytype) @TypeOf(writer).Error!void {
        try std.internal_format(writer, "{}", .{specific.cr3});
    }
};

const Indices = [std.enum_count(PageIndex)]u16;

pub fn map(virtual_address_space: *VirtualAddressSpace, physical_address: PhysicalAddress, virtual_address: VirtualAddress, flags: MemoryFlags) MapError!void {
    var allocation_count: u64 = 0;

    if (true) @panic("TODO vas map");

    if (kernel.config.safe_slow) {
        @panic("TODO safe map map");
        //std.assert((PhysicalAddress{ .value = virtual_address_space.arch.cr3 }).is_valid());
        //std.assert(std.is_aligned(virtual_address.value, common.page_size));
        //std.assert(std.is_aligned(physical_address.value, common.page_size));
    }

    _ = allocation_count;
    _ = flags;
    _ = virtual_address;
    _ = physical_address;
    _ = virtual_address_space;

    //const indices = compute_indices(virtual_address);

    //const is_bootstrapping_address_space = virtual_address_space == kernel.bootstrap_virtual_address_space;

    //var pdp: *volatile PDPTable = undefined;
    //{
    //const pml4_physical_address = get_pml4_physical_address(virtual_address_space);
    //var pml4_virtual_address = VirtualAddress.invalid();
    //const page_count = @divExact(@sizeOf(PML4Table), page_size);
    //_ = page_count;

    //if (is_bootstraping) {
    //if (is_bootstrapping_address_space) {
    //@panic("bootstrapping address space");
    //} else {
    //std.assert(virtual_address_space == &kernel.virtual_address_space);
    //// In this situation, when we rely on the bootloader address space, it's assumed that the PML4 physical address is identity mapped
    //// Check for this fn new in this same module
    //pml4_virtual_address = pml4_physical_address.to_identity_mapped_virtual_address();
    //}
    //} else {
    //std.assert(!is_bootstrapping_address_space);
    //std.assert(virtual_address_space != kernel.bootstrap_virtual_address_space);
    //@panic("ni");
    //}
    //std.assert(pml4_virtual_address.is_valid());

    //var pml4 = pml4_virtual_address.access(*PML4Table);
    //var pml4_entry = &pml4[indices[@enumToInt(PageIndex.PML4)]];
    //var pml4_entry_value = pml4_entry.value;

    //if (pml4_entry_value.contains(.present)) {
    //const entry_physical_address = get_address_from_entry_bits(pml4_entry_value.bits);
    //const entry_virtual_address = if (is_bootstraping) entry_physical_address.to_virtual_address_with_offset(higher_half_direct_map) else entry_physical_address.to_higher_half_virtual_address();
    //pdp = entry_virtual_address.access(*volatile PDPTable);
    //} else {
    //log.debug("PML4 entry value: 0x{x}", .{pml4_entry_value.bits});
    //@panic("pml4 not implemented");
    //}
    //}

    //if (true) @panic("next step");

    //var pd: *volatile PDTable = undefined;
    //{
    //var pdp_entry = &pdp[indices[@enumToInt(PageIndex.PDP)]];
    //var pdp_entry_value = pdp_entry.value;

    //if (pdp_entry_value.contains(.present)) {
    //const entry_physical_address = get_address_from_entry_bits(pdp_entry_value.bits);
    //const entry_virtual_address = if (is_bootstraping and is_bootstrapping_address_space) entry_physical_address.to_virtual_address_with_offset(0) else if (is_bootstraping) entry_physical_address.to_virtual_address_with_offset(higher_half_direct_map) else entry_physical_address.to_higher_half_virtual_address();
    //pd = entry_virtual_address.access(@TypeOf(pd));
    //} else {
    //defer allocation_count += 1;

    //const page_count = @divExact(@sizeOf(PDTable), common.page_size);
    //const entry_physical_address = kernel.physical_address_space.allocate(page_count) orelse @panic("unable to alloc pd");
    //// This address does not need to be mapped since it will be mapped later on when the used physical address space bitset memory
    //const entry_virtual_address = if (is_bootstraping and is_bootstrapping_address_space) entry_physical_address.to_virtual_address_with_offset(0) else if (is_bootstraping) entry_physical_address.to_virtual_address_with_offset(higher_half_direct_map) else entry_physical_address.to_higher_half_virtual_address();
    ////log.debug("Allocating PD: (0x{x}, 0x{x}). Bootstrapping: {}", .{ entry_physical_address.value, entry_virtual_address.value, is_bootstraping });

    //if (is_bootstraping and !is_bootstrapping_address_space) {
    //var mapped = false;
    //if (get_mapped_address_bootstrapping(entry_virtual_address, entry_physical_address, .not_panic)) |mapped_address| {
    //if (mapped_address.value == entry_physical_address.value) mapped = true else @panic("WTF");
    //}

    //if (!mapped) {
    //if (kernel.bootstrap_virtual_address_space.lock.status != 0) {
    //kernel.bootstrap_virtual_address_space.map_extended(entry_physical_address, entry_virtual_address, page_count, .{ .write = true }, VirtualAddressSpace.AlreadyLocked.yes, is_bootstraping, higher_half_direct_map) catch unreachable;
    //} else {
    //kernel.bootstrap_virtual_address_space.map_extended(entry_physical_address, entry_virtual_address, page_count, .{ .write = true }, VirtualAddressSpace.AlreadyLocked.no, is_bootstraping, higher_half_direct_map) catch unreachable;
    //}
    //}

    //_ = get_mapped_address_bootstrapping(entry_virtual_address, entry_physical_address, .panic);
    ////log.debug("#{} Adding 0x{x}", .{ bootstrapping_physical_addresses.items.len, entry_physical_address.value });
    //bootstrapping_physical_addresses.append(kernel.bootstrap_allocator.allocator(), entry_physical_address) catch unreachable;
    //} else {
    //@panic("todo");
    //}

    //pd = entry_virtual_address.access(@TypeOf(pd));
    //pd.* = std.zeroes(PDTable);
    //pdp_entry_value.or_flag(.present);
    //pdp_entry_value.or_flag(.read_write);
    //pdp_entry_value.or_flag(.user);
    //pdp_entry_value.bits = set_entry_in_address_bits(pdp_entry_value.bits, entry_physical_address);
    //pdp_entry.value = pdp_entry_value;
    //}
    //}

    //var pt: *volatile PTable = undefined;
    //{
    //var pd_entry = &pd[indices[@enumToInt(PageIndex.PD)]];
    //var pd_entry_value = pd_entry.value;

    //if (pd_entry_value.contains(.present)) {
    //const entry_physical_address = get_address_from_entry_bits(pd_entry_value.bits);
    //const entry_virtual_address = if (is_bootstraping and is_bootstrapping_address_space) entry_physical_address.to_virtual_address_with_offset(0) else if (is_bootstraping) entry_physical_address.to_virtual_address_with_offset(higher_half_direct_map) else entry_physical_address.to_higher_half_virtual_address();
    //pt = entry_virtual_address.access(@TypeOf(pt));
    //} else {
    //defer allocation_count += 1;

    //const page_count = @divExact(@sizeOf(PDTable), common.page_size);
    //const entry_physical_address = kernel.physical_address_space.allocate(page_count) orelse @panic("unable to alloc pt");
    //const entry_virtual_address = if (is_bootstraping and is_bootstrapping_address_space) entry_physical_address.to_virtual_address_with_offset(0) else if (is_bootstraping) entry_physical_address.to_virtual_address_with_offset(higher_half_direct_map) else entry_physical_address.to_higher_half_virtual_address();
    ////log.debug("Allocating PT: (0x{x}, 0x{x})", .{ entry_physical_address.value, entry_virtual_address.value });

    //if (is_bootstraping and !is_bootstrapping_address_space) {
    //var mapped = false;
    //if (get_mapped_address_bootstrapping(entry_virtual_address, entry_physical_address, .not_panic)) |mapped_address| {
    //if (mapped_address.value == entry_physical_address.value) mapped = true else @panic("WTF");
    //}

    //if (!mapped) {
    //if (kernel.bootstrap_virtual_address_space.lock.status != 0) {
    //kernel.bootstrap_virtual_address_space.map_extended(entry_physical_address, entry_virtual_address, page_count, .{ .write = true }, VirtualAddressSpace.AlreadyLocked.yes, is_bootstraping, higher_half_direct_map) catch unreachable;
    //} else {
    //kernel.bootstrap_virtual_address_space.map_extended(entry_physical_address, entry_virtual_address, page_count, .{ .write = true }, VirtualAddressSpace.AlreadyLocked.no, is_bootstraping, higher_half_direct_map) catch unreachable;
    //}
    //}

    //_ = get_mapped_address_bootstrapping(entry_virtual_address, entry_physical_address, .panic);
    ////log.debug("#{} Adding 0x{x}", .{ bootstrapping_physical_addresses.items.len, entry_physical_address.value });
    //bootstrapping_physical_addresses.append(kernel.bootstrap_allocator.allocator(), entry_physical_address) catch unreachable;
    //} else {
    //@panic("todo");
    //}

    //pt = entry_virtual_address.access(@TypeOf(pt));
    //pt.* = std.zeroes(PTable);
    //pd_entry_value.or_flag(.present);
    //pd_entry_value.or_flag(.read_write);
    //pd_entry_value.or_flag(.user);
    //pd_entry_value.bits = set_entry_in_address_bits(pd_entry_value.bits, entry_physical_address);
    //pd_entry.value = pd_entry_value;
    //}
    //}

    //const pte_ptr = &pt[indices[@enumToInt(PageIndex.PT)]];
    //if (pte_ptr.value.contains(.present)) {
    //const already_mapped_physical_address = pte_ptr.value.bits & address_mask;
    //log.err("Page 0x{x} was already mapped to 0x{x}", .{ virtual_address.value, already_mapped_physical_address });
    //return MapError.already_present;
    //}

    //pte_ptr.* = blk: {
    //var pte = PTE{
    //.value = PTE.Flags.from_bits(flags.bits),
    //};

    //pte.value.or_flag(.present);
    //pte.value.bits = set_entry_in_address_bits(pte.value.bits, physical_address);

    //break :blk pte;
    //};
}

pub fn new(virtual_address_space: *VirtualAddressSpace, physical_address_space: *PhysicalAddressSpace) void {
    const is_kernel_address_space = virtual_address_space == &kernel.virtual_address_space;
    std.assert((virtual_address_space.privilege_level == .kernel) == is_kernel_address_space);

    if (is_kernel_address_space) {
        const half_entry_count = 0x100;
        const pml4_table_page_count = comptime @divExact(@sizeOf(PML4Table), page_size);
        const pdp_table_page_count = comptime @divExact(@sizeOf(PDPTable), page_size);
        const pml4_physical_region = physical_address_space.allocate_pages(page_size, pml4_table_page_count, .{ .zeroed = true }) orelse @panic("wtf");
        for (pml4_physical_region.address.to_higher_half_virtual_address().access([*]const u8)[0..pml4_physical_region.size]) |byte| {
            std.assert(byte == 0);
        }
        const pdp_physical_region = physical_address_space.allocate_pages(page_size, pdp_table_page_count, .{ .zeroed = true }) orelse @panic("wtf");
        for (pdp_physical_region.address.to_higher_half_virtual_address().access([*]const u8)[0..pdp_physical_region.size]) |byte| {
            std.assert(byte == 0);
        }

        if (kernel.config.safe_slow) {
            const top_physical_address = pdp_physical_region.address.offset(pdp_table_page_count * page_size);
            if (top_physical_address.value >= 4 * 1024 * 1024 * 1024) {
                @panic("wtf");
            }
        }

        virtual_address_space.arch = Specific{
            .cr3 = cr3.from_address(pml4_physical_region.address),
        };

        const pml4_virtual_address = pml4_physical_region.address.to_higher_half_virtual_address();
        const pml4 = pml4_virtual_address.access(*PML4Table);
        const lower_half_pml4 = pml4[0 .. pml4.len / 2];
        const higher_half_pml4 = pml4[0 .. pml4.len / 2];
        std.assert(lower_half_pml4.len == half_entry_count);
        std.assert(higher_half_pml4.len == half_entry_count);
        std.zero_slice(PML4Entry, lower_half_pml4);

        var pdp_table_physical_address = pdp_physical_region.address;
        for (higher_half_pml4) |*pml4_entry| {
            defer pdp_table_physical_address.value += @sizeOf(PDPTable);
            pml4_entry.* = PML4Entry{
                .present = true,
                .read_write = true,
                .address = pack_address(pdp_table_physical_address),
            };
        }
    } else {
        @panic("TODO: implement user address spaces");
    }
}

pub fn bootstrap_map(asked_physical_address: PhysicalAddress, asked_virtual_address: VirtualAddress, page_count: u64, general_flags: VirtualAddressSpace.Flags) void {
    const flags = general_flags.to_arch_specific();
    _ = flags;

    std.assert(page_count > 0);

    var virtual_address = asked_virtual_address;
    var physical_address = asked_physical_address;
    const top_virtual_address = asked_virtual_address.offset(page_count * page_size);

    while (virtual_address.value < top_virtual_address.value) : ({
        physical_address.value += page_size;
        virtual_address.value += page_size;
    }) {
        const log_this = false; //0xffff800040000000 - virtual_address.value < 0x10000;

        std.assert(virtual_address.is_valid());
        std.assert(std.is_aligned(virtual_address.value, x86_64.page_size));

        const indices = compute_indices(virtual_address);
        const virtual_address_space = &kernel.virtual_address_space;

        const pml4_table = blk: {
            const pml4_physical_address = virtual_address_space.arch.cr3.get_address();
            const pml4_virtual_address = pml4_physical_address.to_higher_half_virtual_address();
            if (log_this) {
                log.debug("PML4: {}", .{pml4_virtual_address});
            }
            if (kernel.config.safe_slow) {
                std.assert(pml4_virtual_address.is_valid());
            }

            break :blk pml4_virtual_address.access(*volatile PML4Table);
        };

        const pdp_table = blk: {
            const entry_pointer = &pml4_table[indices[@enumToInt(PageIndex.PML4)]];
            if (log_this) log.debug("PDP index: {}", .{indices[@enumToInt(PageIndex.PML4)]});

            const table_physical_address = physical_address_blk: {
                const entry_value = entry_pointer.*;
                if (log_this) log.debug("Entry value: {}", .{entry_value});
                if (entry_value.present) {
                    if (log_this) log.debug("Present", .{});
                    break :physical_address_blk unpack_address(entry_value);
                } else {
                    if (log_this) log.debug("Not present", .{});
                    const entry_page_count = @divExact(@sizeOf(PDPTable), page_size);
                    // TODO: track this physical allocation in order to map it later in the kernel address space
                    const entry_physical_region = kernel.physical_address_space.allocate_pages(page_size, entry_page_count, .{ .zeroed = true }) orelse @panic("WTF");
                    if (kernel.config.safe_slow) {
                        for (entry_physical_region.address.to_higher_half_virtual_address().access([*]const u8)[0..entry_physical_region.size]) |byte| {
                            std.assert(byte == 0);
                        }
                    }

                    entry_pointer.* = PML4Entry{
                        .present = true,
                        .read_write = true,
                        .address = pack_address(entry_physical_region.address),
                    };

                    break :physical_address_blk entry_physical_region.address;
                }
            };

            if (log_this) {
                log.debug("Table physical address: {}", .{table_physical_address});
            }

            const table_virtual_address = table_physical_address.to_higher_half_virtual_address();
            if (kernel.config.safe_slow) std.assert(table_virtual_address.is_valid());
            break :blk table_virtual_address.access(*volatile PDPTable);
        };

        const pd_table = blk: {
            const entry_pointer = &pdp_table[indices[@enumToInt(PageIndex.PDP)]];
            if (log_this) {
                log.debug("PD index: {}", .{indices[@enumToInt(PageIndex.PDP)]});
            }

            const table_physical_address = physical_address_blk: {
                const entry_value = entry_pointer.*;
                if (log_this) log.debug("Entry value: {}", .{entry_value});
                if (entry_value.present) {
                    if (log_this) log.debug("Present", .{});
                    // The address is mapped with a 1GB page
                    if (entry_value.page_size) {
                        @panic("todo pd table page size");
                    }
                    break :physical_address_blk unpack_address(entry_value);
                } else {
                    if (log_this) log.debug("Not present", .{});
                    const entry_page_count = @divExact(@sizeOf(PDTable), page_size);
                    // TODO: track this physical allocation in order to map it later in the kernel address space
                    const entry_physical_region = kernel.physical_address_space.allocate_pages(page_size, entry_page_count, .{ .zeroed = true }) orelse @panic("WTF");
                    if (kernel.config.safe_slow) {
                        for (entry_physical_region.address.to_higher_half_virtual_address().access([*]const u8)[0..entry_physical_region.size]) |byte| {
                            std.assert(byte == 0);
                        }
                    }

                    entry_pointer.* = PDPEntry{
                        .present = true,
                        .read_write = true,
                        .address = pack_address(entry_physical_region.address),
                    };

                    break :physical_address_blk entry_physical_region.address;
                }
            };
            if (log_this) log.debug("Table physical address: {}", .{table_physical_address});

            const table_virtual_address = table_physical_address.to_higher_half_virtual_address();
            if (kernel.config.safe_slow) std.assert(table_virtual_address.is_valid());
            break :blk table_virtual_address.access(*volatile PDTable);
        };

        const p_table = blk: {
            const entry_pointer = &pd_table[indices[@enumToInt(PageIndex.PD)]];
            if (log_this) log.debug("PT index: {}", .{indices[@enumToInt(PageIndex.PD)]});

            const table_physical_address = physical_address_blk: {
                const entry_value = entry_pointer.*;
                if (log_this) log.debug("Entry value: {}", .{entry_value});
                if (entry_value.present) {
                    if (log_this) log.debug("Present", .{});
                    // The address is mapped with a 2MB page
                    if (entry_value.page_size) {
                        @panic("todo ptable page size");
                    }
                    break :physical_address_blk unpack_address(entry_value);
                } else {
                    if (log_this) log.debug("Not present", .{});
                    const entry_page_count = @divExact(@sizeOf(PDTable), page_size);
                    // TODO: track this physical allocation in order to map it later in the kernel address space
                    const entry_physical_region = kernel.physical_address_space.allocate_pages(page_size, entry_page_count, .{ .zeroed = true }) orelse @panic("WTF");
                    if (log_this) {
                        log.debug("Entry physical region: {}", .{entry_physical_region.address});
                    }

                    if (kernel.config.safe_slow) {
                        for (entry_physical_region.address.to_higher_half_virtual_address().access([*]const u8)[0..entry_physical_region.size]) |byte| {
                            std.assert(byte == 0);
                        }
                    }

                    entry_pointer.* = PDEntry{
                        .present = true,
                        .read_write = true,
                        .address = pack_address(entry_physical_region.address),
                    };

                    break :physical_address_blk entry_physical_region.address;
                }
            };

            if (log_this) log.debug("Table physical_address: {}", .{table_physical_address});

            const table_virtual_address = table_physical_address.to_higher_half_virtual_address();
            if (kernel.config.safe_slow) std.assert(table_virtual_address.is_valid());
            break :blk table_virtual_address.access(*volatile PTable);
        };
        if (log_this) {
            for (p_table) |p_entry| {
                log.debug("P Entry: 0x{x}", .{@bitCast(u64, p_entry)});
            }
        }

        const entry_pointer = &p_table[indices[@enumToInt(PageIndex.PT)]];
        if (log_this) log.debug("P Index: {}", .{indices[@enumToInt(PageIndex.PT)]});
        const entry_value = entry_pointer.*;
        if (log_this) log.debug("Entry value: {}", .{entry_value});

        if (entry_value.present) {
            crash.panic("Virtual address {} already present in CR3 {}. Translated to {}. Debug: 0x{x}", .{ virtual_address, virtual_address_space.arch.cr3.get_address(), unpack_address(entry_value), @bitCast(u64, entry_value) & 0xffff_ffff_ffff_f000 });
        }

        entry_pointer.* = PTEntry{
            .present = true,
            .read_write = true,
            .address = pack_address(physical_address),
        };

        if (kernel.config.safe_slow) {
            const translated_address = virtual_address_space.translate_address(virtual_address) orelse unreachable;
            if (translated_address.value != physical_address.value) @panic("WTF seriously");
        }
    }
}

const time_map = false;

const PanicPolicy = enum {
    panic,
    not_panic,
};

pub inline fn switch_address_spaces_if_necessary(new_address_space: *VirtualAddressSpace) void {
    _ = new_address_space;
    @panic("TODO: switch address spaces if necessary");
    //const current_cr3 = cr3.read_raw();
    //if (current_cr3 != new_address_space.arch.cr3) {
    //cr3.write_raw(new_address_space.arch.cr3);
    //}
}

pub inline fn is_current(virtual_address_space: *VirtualAddressSpace) bool {
    _ = virtual_address_space;
    return false;
    //const current = cr3.read_raw();
    //return current == virtual_address_space.arch.cr3;
}

pub inline fn from_current(virtual_address_space: *VirtualAddressSpace) void {
    virtual_address_space.* = VirtualAddressSpace{
        .arch = Specific{
            .cr3 = cr3.read(),
        },
        .privilege_level = .kernel,
        .heap = .{},
        .lock = .{},
    };
}

pub fn map_kernel_address_space_higher_half(virtual_address_space: *VirtualAddressSpace, kernel_address_space: *VirtualAddressSpace) void {
    _ = virtual_address_space;
    _ = kernel_address_space;
    @panic("TODO: map kernel address space higher_half");
    //const cr3_physical_address = PhysicalAddress.new(virtual_address_space.arch.cr3);
    //const cr3_kernel_virtual_address = cr3_physical_address.to_higher_half_virtual_address();
    //// TODO: maybe user flag is not necessary?
    //kernel_address_space.map(cr3_physical_address, cr3_kernel_virtual_address, 1, .{ .write = true, .user = true }) catch unreachable;
    //const pml4 = cr3_kernel_virtual_address.access(*PML4Table);
    //std.zero_slice(PML4E, pml4[0..0x100]);
    //if (true) @panic("fix this map kernel address space higher half");
    ////std.copy(PML4E, pml4[0x100..], PhysicalAddress.new(kernel_address_space.arch.cr3).access_higher_half(*PML4Table)[0x100..]);
    //log.debug("USER CR3: 0x{x}", .{cr3_physical_address.value});
}

pub fn translate_address(virtual_address_space: *VirtualAddressSpace, asked_virtual_address: VirtualAddress) TranslationResult {
    std.assert(asked_virtual_address.is_valid());
    if (!std.is_aligned(asked_virtual_address.value, x86_64.page_size)) {
        log.err("Virtual address {} not aligned", .{asked_virtual_address});
        return std.zeroes(TranslationResult);
    }

    const virtual_address = asked_virtual_address;
    const indices = compute_indices(virtual_address);
    _ = indices;

    const pml4_table = blk: {
        const pml4_physical_address = virtual_address_space.arch.cr3.get_address();
        const pml4_virtual_address = pml4_physical_address.to_higher_half_virtual_address();
        if (kernel.config.safe_slow) {
            std.assert(pml4_virtual_address.is_valid());
        }

        break :blk pml4_virtual_address.access(*volatile PML4Table);
    };

    const pdp_table = blk: {
        const pml4_entry = pml4_table[indices[@enumToInt(PageIndex.PML4)]];
        if (!pml4_entry.present) {
            //log.err("Virtual address {} not present: PML4", .{virtual_address});
            return std.zeroes(TranslationResult);
        }

        const pdp_table_virtual_address = unpack_address(pml4_entry).to_higher_half_virtual_address();
        if (kernel.config.safe_slow) std.assert(pdp_table_virtual_address.is_valid());
        break :blk pdp_table_virtual_address.access(*volatile PDPTable);
    };

    const pd_table = blk: {
        const pdp_entry = pdp_table[indices[@enumToInt(PageIndex.PDP)]];
        if (!pdp_entry.present) {
            //log.err("Virtual address {} not present: PDP", .{virtual_address});
            return std.zeroes(TranslationResult);
        }

        const physical_address = unpack_address(pdp_entry);
        // The address is mapped with a 1 GB page
        if (pdp_entry.page_size) {
            return TranslationResult{
                .physical_address = physical_address,
                .page_size = 1024 * 1024 * 1024,
                .mapped = true,
            };
        }

        const pd_table_virtual_address = physical_address.to_higher_half_virtual_address();
        if (kernel.config.safe_slow) std.assert(pd_table_virtual_address.is_valid());
        break :blk pd_table_virtual_address.access(*volatile PDTable);
    };

    const p_table = blk: {
        const pd_entry = pd_table[indices[@enumToInt(PageIndex.PD)]];
        if (!pd_entry.present) {
            //log.err("Virtual address {} not present: PD", .{virtual_address});
            return std.zeroes(TranslationResult);
        }

        const physical_address = unpack_address(pd_entry);
        // The address is mapped with a 2MB page
        if (pd_entry.page_size) {
            return TranslationResult{
                .physical_address = physical_address,
                .page_size = 2 * 1024 * 1024,
                .mapped = true,
            };
        }
        const p_table_virtual_address = physical_address.to_higher_half_virtual_address();
        if (kernel.config.safe_slow) std.assert(p_table_virtual_address.is_valid());
        break :blk p_table_virtual_address.access(*volatile PDTable);
    };

    const p_entry = p_table[indices[@enumToInt(PageIndex.PT)]];
    if (!p_entry.present) {
        return std.zeroes(TranslationResult);
    }

    const physical_address = unpack_address(p_entry);
    return TranslationResult{
        .physical_address = physical_address,
        .page_size = 0x1000,
        .mapped = true,
    };
}

fn compute_indices(virtual_address: VirtualAddress) Indices {
    var indices: Indices = undefined;
    var va = virtual_address.value;
    va = va >> 12;
    indices[3] = @truncate(u9, va);
    va = va >> 9;
    indices[2] = @truncate(u9, va);
    va = va >> 9;
    indices[1] = @truncate(u9, va);
    va = va >> 9;
    indices[0] = @truncate(u9, va);

    return indices;
}

pub fn make_current(virtual_address_space: *VirtualAddressSpace) void {
    if (kernel.config.safe_slow) {
        if (virtual_address_space == &kernel.virtual_address_space) {
            log.debug("About to switch to kernel address space", .{});
            const instruction_pointer = VirtualAddress.new(@returnAddress()).aligned_backward(page_size);
            const frame_pointer = VirtualAddress.new(@frameAddress()).aligned_backward(page_size);
            const global_ptr_va = VirtualAddress.new(@ptrToInt(&kernel.virtual_address_space)).aligned_backward(page_size);
            const RBP = registers.rbp.read();
            log.debug("RBP: 0x{x}", .{RBP});

            const instruction_pointer_physical_address = kernel.bootstrap_virtual_address_space.translate_address(instruction_pointer) orelse unreachable;
            const frame_pointer_physical_address = kernel.bootstrap_virtual_address_space.translate_address(frame_pointer) orelse unreachable;
            const global_pointer_physical_address = kernel.bootstrap_virtual_address_space.translate_address(global_ptr_va) orelse unreachable;

            log.debug("Checking if instruction pointer is mapped to {}...", .{instruction_pointer_physical_address});
            std.assert(virtual_address_space.translate_address(instruction_pointer) != null);
            log.debug("Checking if frame pointer is mapped to {}...", .{frame_pointer_physical_address});
            std.assert(virtual_address_space.translate_address(frame_pointer) != null);
            log.debug("Checking if a global variable is mapped to {}...", .{global_pointer_physical_address});
            std.assert(virtual_address_space.translate_address(global_ptr_va) != null);

            std.assert(virtual_address_space.translate_address(virtual_address_space.arch.cr3.get_address().to_higher_half_virtual_address()) != null);
        }
    }

    log.debug("Writing CR3: 0x{x}", .{@bitCast(u64, virtual_address_space.arch.cr3)});
    virtual_address_space.arch.cr3.write();
}

pub inline fn new_flags(general_flags: VirtualAddressSpace.Flags) MemoryFlags {
    return MemoryFlags{
        .read_write = general_flags.write,
        .user = general_flags.user,
        .cache_disable = general_flags.cache_disable,
        .accessed = general_flags.accessed,
        .execute_disable = general_flags.execute,
    };
}

// TODO:
pub const MemoryFlags = packed struct(u64) {
    present: bool = true,
    read_write: bool = false,
    user: bool = false,
    write_through: bool = false,
    cache_disable: bool = false,
    accessed: bool = false,
    dirty: bool = false,
    pat: bool = false,
    global: bool = false,
    reserved: u54 = 0,
    execute_disable: bool = false,

    comptime {
        std.assert(@sizeOf(u64) == @sizeOf(MemoryFlags));
    }
};

const address_mask: u64 = 0x0000_00ff_ffff_f000;

fn set_entry_in_address_bits(old_entry_value: u64, new_address: PhysicalAddress) u64 {
    if (kernel.config.safe_slow) {
        std.assert(x86_64.max_physical_address_bit == 40);
        std.assert(std.is_aligned(new_address.value, common.page_size));
    }

    const address_masked = new_address.value & address_mask;
    const old_entry_value_masked = old_entry_value & ~address_masked;
    const result = address_masked | old_entry_value_masked;

    return result;
}

inline fn get_address_from_entry_bits(entry_bits: u64) PhysicalAddress {
    const address = entry_bits & address_mask;
    if (kernel.config.safe_slow) {
        std.assert(common.max_physical_address_bit == 40);
        std.assert(std.is_aligned(address, common.page_size));
    }

    return PhysicalAddress.new(address);
}

const PageIndex = enum(u3) {
    PML4 = 0,
    PDP = 1,
    PD = 2,
    PT = 3,
};

fn unpack_address(entry: anytype) PhysicalAddress {
    return PhysicalAddress.new(@as(u64, entry.address) << x86_64.page_shifter);
}

inline fn pack_address(physical_address: PhysicalAddress) u28 {
    return @intCast(u28, physical_address.value >> x86_64.page_shifter);
}

const PML4Entry = packed struct(u64) {
    present: bool = false,
    read_write: bool = false,
    user: bool = false,
    page_level_write_through: bool = false,
    page_level_cache_disable: bool = false,
    accessed: bool = false,
    reserved0: u5 = 0,
    hlat_restart: bool = false,
    address: u28,
    reserved1: u23 = 0,
    execute_disable: bool = false,

    comptime {
        std.assert(@sizeOf(@This()) == @sizeOf(u64));
        std.assert(@bitSizeOf(@This()) == @bitSizeOf(u64));
    }
};

const PDPEntry = packed struct(u64) {
    present: bool = false,
    read_write: bool = false,
    user: bool = false,
    page_level_write_through: bool = false,
    page_level_cache_disable: bool = false,
    accessed: bool = false,
    reserved0: u1 = 0,
    page_size: bool = false,
    reserved1: u3 = 0,
    hlat_restart: bool = false,
    address: u28,
    reserved2: u23 = 0,
    execute_disable: bool = false,

    comptime {
        std.assert(@sizeOf(@This()) == @sizeOf(u64));
        std.assert(@bitSizeOf(@This()) == @bitSizeOf(u64));
    }
};

const PDEntry = packed struct(u64) {
    present: bool = false,
    read_write: bool = false,
    user: bool = false,
    page_level_write_through: bool = false,
    page_level_cache_disable: bool = false,
    accessed: bool = false,
    reserved0: u1 = 0,
    page_size: bool = false,
    reserved1: u3 = 0,
    hlat_restart: bool = false,
    address: u28,
    reserved2: u23 = 0,
    execute_disable: bool = false,

    comptime {
        std.assert(@sizeOf(@This()) == @sizeOf(u64));
        std.assert(@bitSizeOf(@This()) == @bitSizeOf(u64));
    }
};

const PTEntry = packed struct(u64) {
    present: bool = false,
    read_write: bool = false,
    user: bool = false,
    page_level_write_through: bool = false,
    page_level_cache_disable: bool = false,
    accessed: bool = false,
    dirty: bool = false,
    pat: bool = false,
    global: bool = false,
    reserved1: u2 = 0,
    hlat_restart: bool = false,
    address: u28,
    reserved2: u23 = 0,
    execute_disable: bool = false,

    comptime {
        std.assert(@sizeOf(@This()) == @sizeOf(u64));
        std.assert(@bitSizeOf(@This()) == @bitSizeOf(u64));
    }
};

const PML4Table = [512]PML4Entry;
const PDPTable = [512]PDPEntry;
const PDTable = [512]PDEntry;
const PTable = [512]PTEntry;

const common = @import("common");
const assert = common.assert;
const copy = common.copy;
const enum_count = common.enum_count;
const is_aligned = common.is_aligned;
const log = common.log.scoped(.VAS);
const zeroes = common.zeroes;
const zero_slice = common.zero_slice;

const RNU = @import("RNU");
const panic = RNU.panic;
const PhysicalAddress = RNU.PhysicalAddress;
const PhysicalAddressSpace = RNU.PhysicalAddressSpace;
const VirtualAddress = RNU.VirtualAddress;
const VirtualAddressSpace = RNU.VirtualAddressSpace;
const MapError = VirtualAddressSpace.MapError;
const TranslationResult = VirtualAddressSpace.TranslationResult;

const kernel = @import("kernel");

const arch = @import("arch");
const page_size = arch.page_size;
const x86_64 = arch.x86_64;
const cr3 = x86_64.registers.cr3;

pub const Specific = struct {
    cr3: cr3 = undefined,

    pub fn format(specific: Specific, comptime _: []const u8, _: common.InternalFormatOptions, writer: anytype) @TypeOf(writer).Error!void {
        try common.internal_format(writer, "{}", .{specific.cr3});
    }
};

const Indices = [enum_count(PageIndex)]u16;

pub fn map(virtual_address_space: *VirtualAddressSpace, physical_address: PhysicalAddress, virtual_address: VirtualAddress, flags: MemoryFlags) MapError!void {
    if (kernel.config.safe_slow) {
        assert(virtual_address_space != kernel.bootstrap_virtual_address_space);
        assert(is_aligned(virtual_address.value, common.page_size));
        assert(is_aligned(physical_address.value, common.page_size));
    }

    const indices = compute_indices(virtual_address);
    const pml4_table = blk: {
        const pml4_physical_address = virtual_address_space.arch.cr3.get_address();
        if (kernel.config.safe_slow) {
            assert(pml4_physical_address.is_valid());
        }
        const pml4_virtual_address = pml4_physical_address.to_higher_half_virtual_address();
        if (kernel.config.safe_slow) {
            assert(pml4_virtual_address.is_valid());
        }

        break :blk pml4_virtual_address.access(*volatile PML4Table);
    };
    const pdp_table = blk: {
        const entry_pointer = &pml4_table[indices[@enumToInt(PageIndex.PML4)]];

        const table_physical_address = physical_address_blk: {
            const entry_value = entry_pointer.*;
            if (entry_value.present) {
                break :physical_address_blk unpack_address(entry_value);
            } else {
                const entry_page_count = @divExact(@sizeOf(PDPTable), page_size);
                // TODO: track this physical allocation in order to map it later in the kernel address space
                const entry_physical_region = kernel.physical_address_space.allocate_pages(page_size, entry_page_count, .{ .zeroed = true }) orelse @panic("WTF");
                if (kernel.config.safe_slow) {
                    for (entry_physical_region.address.to_higher_half_virtual_address().access([*]const u8)[0..entry_physical_region.size]) |byte| {
                        assert(byte == 0);
                    }
                }

                entry_pointer.* = PML4Entry{
                    .present = true,
                    .read_write = true,
                    .user = true,
                    .address = pack_address(entry_physical_region.address),
                };

                break :physical_address_blk entry_physical_region.address;
            }
        };

        const table_virtual_address = table_physical_address.to_higher_half_virtual_address();
        if (kernel.config.safe_slow) assert(table_virtual_address.is_valid());
        break :blk table_virtual_address.access(*volatile PDPTable);
    };
    const pd_table = blk: {
        const entry_pointer = &pdp_table[indices[@enumToInt(PageIndex.PDP)]];

        const table_physical_address = physical_address_blk: {
            const entry_value = entry_pointer.*;
            if (entry_value.present) {
                // The address is mapped with a 1GB page
                if (entry_value.page_size) {
                    @panic("todo pd table page size");
                }
                break :physical_address_blk unpack_address(entry_value);
            } else {
                const entry_page_count = @divExact(@sizeOf(PDTable), page_size);
                // TODO: track this physical allocation in order to map it later in the kernel address space
                const entry_physical_region = kernel.physical_address_space.allocate_pages(page_size, entry_page_count, .{ .zeroed = true }) orelse @panic("WTF");
                if (kernel.config.safe_slow) {
                    for (entry_physical_region.address.to_higher_half_virtual_address().access([*]const u8)[0..entry_physical_region.size]) |byte| {
                        assert(byte == 0);
                    }
                }

                entry_pointer.* = PDPEntry{
                    .present = true,
                    .read_write = true,
                    .user = true,
                    .address = pack_address(entry_physical_region.address),
                };

                break :physical_address_blk entry_physical_region.address;
            }
        };

        const table_virtual_address = table_physical_address.to_higher_half_virtual_address();
        if (kernel.config.safe_slow) assert(table_virtual_address.is_valid());
        break :blk table_virtual_address.access(*volatile PDTable);
    };

    const p_table = blk: {
        const entry_pointer = &pd_table[indices[@enumToInt(PageIndex.PD)]];

        const table_physical_address = physical_address_blk: {
            const entry_value = entry_pointer.*;
            if (entry_value.present) {
                // The address is mapped with a 2MB page
                if (entry_value.page_size) {
                    @panic("todo ptable page size");
                }
                break :physical_address_blk unpack_address(entry_value);
            } else {
                const entry_page_count = @divExact(@sizeOf(PDTable), page_size);
                // TODO: track this physical allocation in order to map it later in the kernel address space
                const entry_physical_region = kernel.physical_address_space.allocate_pages(page_size, entry_page_count, .{ .zeroed = true }) orelse @panic("WTF");
                if (kernel.config.safe_slow) {
                    for (entry_physical_region.address.to_higher_half_virtual_address().access([*]const u8)[0..entry_physical_region.size]) |byte| {
                        assert(byte == 0);
                    }
                }

                entry_pointer.* = PDEntry{
                    .present = true,
                    .read_write = true,
                    .user = true,
                    .address = pack_address(entry_physical_region.address),
                };

                break :physical_address_blk entry_physical_region.address;
            }
        };

        const table_virtual_address = table_physical_address.to_higher_half_virtual_address();
        if (kernel.config.safe_slow) assert(table_virtual_address.is_valid());
        break :blk table_virtual_address.access(*volatile PTable);
    };

    const entry_pointer = &p_table[indices[@enumToInt(PageIndex.PT)]];
    const entry_value = entry_pointer.*;

    if (entry_value.present) {
        panic("Virtual address {} already present in CR3 {}. Translated to {}. Debug: 0x{x}", .{ virtual_address, virtual_address_space.arch.cr3.get_address(), unpack_address(entry_value), @bitCast(u64, entry_value) & 0xffff_ffff_ffff_f000 });
    }

    entry_pointer.* = PTEntry{
        .present = true,
        .read_write = flags.read_write,
        .user = flags.user,
        .page_level_cache_disable = flags.cache_disable,
        .global = flags.global,
        .address = pack_address(physical_address),
        .execute_disable = flags.execute_disable,
    };

    if (kernel.config.safe_slow) {
        const translation_result = virtual_address_space.translate_address_extended(virtual_address, .yes);
        if (!translation_result.mapped) {
            @panic("WTF seriously 1");
        }
        if (translation_result.physical_address.value != physical_address.value) {
            @panic("WTF seriously 2");
        }
    }
}

pub fn bootstrap_map(asked_physical_address: PhysicalAddress, asked_virtual_address: VirtualAddress, page_count: u64, general_flags: VirtualAddressSpace.Flags) void {
    // TODO: use flags
    const flags = general_flags.to_arch_specific();
    _ = flags;

    if (kernel.config.safe_slow) {
        assert(page_count > 0);
        assert(asked_virtual_address.is_valid());
        assert(asked_physical_address.is_valid());
        assert(is_aligned(asked_virtual_address.value, x86_64.page_size));
        assert(is_aligned(asked_physical_address.value, x86_64.page_size));
    }

    var virtual_address = asked_virtual_address;
    var physical_address = asked_physical_address;
    const top_virtual_address = asked_virtual_address.offset(page_count * page_size);
    const virtual_address_space = kernel.virtual_address_space;

    while (virtual_address.value < top_virtual_address.value) : ({
        physical_address.value += page_size;
        virtual_address.value += page_size;
    }) {
        const log_this = false; //0xffff800040000000 - virtual_address.value < 0x10000;

        const indices = compute_indices(virtual_address);

        const pml4_table = blk: {
            const pml4_physical_address = virtual_address_space.arch.cr3.get_address();
            const pml4_virtual_address = pml4_physical_address.to_higher_half_virtual_address();
            if (log_this) {
                log.debug("PML4: {}", .{pml4_virtual_address});
            }
            if (kernel.config.safe_slow) {
                assert(pml4_virtual_address.is_valid());
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
                            assert(byte == 0);
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
            if (kernel.config.safe_slow) assert(table_virtual_address.is_valid());
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
                            assert(byte == 0);
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
            if (kernel.config.safe_slow) assert(table_virtual_address.is_valid());
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
                            assert(byte == 0);
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
            if (kernel.config.safe_slow) assert(table_virtual_address.is_valid());
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
            panic("Virtual address {} already present in CR3 {}. Translated to {}. Debug: 0x{x}", .{ virtual_address, virtual_address_space.arch.cr3.get_address(), unpack_address(entry_value), @bitCast(u64, entry_value) & 0xffff_ffff_ffff_f000 });
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

const half_entry_count = (@sizeOf(PML4Table) / @sizeOf(PML4Entry)) / 2;
pub fn init_kernel(virtual_address_space: *VirtualAddressSpace, physical_address_space: *PhysicalAddressSpace) void {
    if (kernel.config.safe_slow) assert(virtual_address_space.privilege_level == .kernel);

    const pml4_table_page_count = comptime @divExact(@sizeOf(PML4Table), page_size);
    const pdp_table_page_count = comptime @divExact(@sizeOf(PDPTable), page_size);
    const pml4_physical_region = physical_address_space.allocate_pages(page_size, pml4_table_page_count, .{ .zeroed = true }) orelse @panic("wtf");
    const pdp_physical_region = physical_address_space.allocate_pages(page_size, pdp_table_page_count, .{ .zeroed = true }) orelse @panic("wtf");

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
    assert(lower_half_pml4.len == half_entry_count);
    assert(higher_half_pml4.len == half_entry_count);
    zero_slice(PML4Entry, lower_half_pml4);

    var pdp_table_physical_address = pdp_physical_region.address;
    for (higher_half_pml4) |*pml4_entry| {
        defer pdp_table_physical_address.value += @sizeOf(PDPTable);
        pml4_entry.* = PML4Entry{
            .present = true,
            .read_write = true,
            .user = true,
            .address = pack_address(pdp_table_physical_address),
        };
    }
}

pub fn init_user(virtual_address_space: *VirtualAddressSpace) void {
    if (kernel.config.safe_slow) assert(virtual_address_space.privilege_level == .user);
    const pml4_table_page_count = comptime @divExact(@sizeOf(PML4Table), page_size);
    const pml4_physical_region = kernel.physical_address_space.allocate_pages(page_size, pml4_table_page_count, .{ .zeroed = true }) orelse @panic("wtf");
    virtual_address_space.arch = Specific{
        .cr3 = cr3.from_address(pml4_physical_region.address),
    };

    const pml4_virtual_address = pml4_physical_region.address.to_higher_half_virtual_address();
    const pml4 = pml4_virtual_address.access(*PML4Table);
    const lower_half_pml4 = pml4[0 .. pml4.len / 2];
    const higher_half_pml4 = pml4[0 .. pml4.len / 2];
    zero_slice(PML4Entry, lower_half_pml4);

    if (kernel.config.safe_slow) {
        assert(lower_half_pml4.len == half_entry_count);
        assert(higher_half_pml4.len == half_entry_count);
    }

    map_kernel_address_space_higher_half(virtual_address_space, kernel.virtual_address_space);
}

const time_map = false;

const PanicPolicy = enum {
    panic,
    not_panic,
};

pub inline fn switch_address_spaces_if_necessary(new_address_space: *VirtualAddressSpace) void {
    const current_cr3 = cr3.read();
    if (@bitCast(u64, current_cr3) != @bitCast(u64, new_address_space.arch.cr3)) {
        new_address_space.arch.cr3.write();
    }
}

pub inline fn is_current(virtual_address_space: *VirtualAddressSpace) bool {
    const vas_cr3 = virtual_address_space.arch.cr3;
    const current_cr3 = cr3.read();
    return current_cr3.equal(vas_cr3);
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
    const cr3_physical_address = virtual_address_space.arch.cr3.get_address();
    const cr3_virtual_address = cr3_physical_address.to_higher_half_virtual_address();
    // TODO: maybe user flag is not necessary?
    const pml4 = cr3_virtual_address.access(*PML4Table);
    zero_slice(PML4Entry, pml4[0..0x100]);
    copy(PML4Entry, pml4[0x100..], kernel_address_space.arch.cr3.get_address().to_higher_half_virtual_address().access(*PML4Table)[0x100..]);
    log.debug("USER CR3: 0x{x}", .{cr3_physical_address.value});
}

pub fn translate_address(virtual_address_space: *VirtualAddressSpace, asked_virtual_address: VirtualAddress) TranslationResult {
    assert(asked_virtual_address.is_valid());
    if (!is_aligned(asked_virtual_address.value, x86_64.page_size)) {
        log.err("Virtual address {} not aligned", .{asked_virtual_address});
        return zeroes(TranslationResult);
    }

    const virtual_address = asked_virtual_address;
    const indices = compute_indices(virtual_address);

    const pml4_table = blk: {
        const pml4_physical_address = virtual_address_space.arch.cr3.get_address();
        const pml4_virtual_address = pml4_physical_address.to_higher_half_virtual_address();
        if (kernel.config.safe_slow) {
            assert(pml4_virtual_address.is_valid());
        }

        break :blk pml4_virtual_address.access(*volatile PML4Table);
    };

    const pdp_table = blk: {
        const pml4_entry = pml4_table[indices[@enumToInt(PageIndex.PML4)]];
        if (!pml4_entry.present) {
            //log.err("Virtual address {} not present: PML4", .{virtual_address});
            return zeroes(TranslationResult);
        }

        const pdp_table_virtual_address = unpack_address(pml4_entry).to_higher_half_virtual_address();
        if (kernel.config.safe_slow) assert(pdp_table_virtual_address.is_valid());
        break :blk pdp_table_virtual_address.access(*volatile PDPTable);
    };

    const pd_table = blk: {
        const pdp_entry = pdp_table[indices[@enumToInt(PageIndex.PDP)]];
        if (!pdp_entry.present) {
            //log.err("Virtual address {} not present: PDP", .{virtual_address});
            return zeroes(TranslationResult);
        }

        const physical_address = unpack_address(pdp_entry);
        // The address is mapped with a 1 GB page
        if (pdp_entry.page_size) {
            return TranslationResult{
                .physical_address = physical_address,
                .page_size = 1024 * 1024 * 1024,
                .mapped = true,
                .flags = .{
                    .write = pdp_entry.read_write,
                    .user = pdp_entry.user,
                    .cache_disable = pdp_entry.page_level_cache_disable,
                    .execute = !pdp_entry.execute_disable,
                },
            };
        }

        const pd_table_virtual_address = physical_address.to_higher_half_virtual_address();
        if (kernel.config.safe_slow) assert(pd_table_virtual_address.is_valid());
        break :blk pd_table_virtual_address.access(*volatile PDTable);
    };

    const p_table = blk: {
        const pd_entry = pd_table[indices[@enumToInt(PageIndex.PD)]];
        if (!pd_entry.present) {
            //log.err("Virtual address {} not present: PD", .{virtual_address});
            return zeroes(TranslationResult);
        }

        const physical_address = unpack_address(pd_entry);
        // The address is mapped with a 2MB page
        if (pd_entry.page_size) {
            return TranslationResult{
                .physical_address = physical_address,
                .page_size = 2 * 1024 * 1024,
                .mapped = true,
                .flags = .{
                    .write = pd_entry.read_write,
                    .user = pd_entry.user,
                    .cache_disable = pd_entry.page_level_cache_disable,
                    .execute = !pd_entry.execute_disable,
                },
            };
        }

        const p_table_virtual_address = physical_address.to_higher_half_virtual_address();
        if (kernel.config.safe_slow) assert(p_table_virtual_address.is_valid());
        break :blk p_table_virtual_address.access(*volatile PDTable);
    };

    const p_entry = p_table[indices[@enumToInt(PageIndex.PT)]];
    if (!p_entry.present) {
        return zeroes(TranslationResult);
    }

    const physical_address = unpack_address(p_entry);
    return TranslationResult{
        .physical_address = physical_address,
        .page_size = 0x1000,
        .mapped = true,
        .flags = .{
            .write = p_entry.read_write,
            .user = p_entry.user,
            .cache_disable = p_entry.page_level_cache_disable,
            .execute = !p_entry.execute_disable,
        },
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

            const instruction_pointer_physical_address = kernel.bootstrap_virtual_address_space.translate_address(instruction_pointer) orelse unreachable;
            const frame_pointer_physical_address = kernel.bootstrap_virtual_address_space.translate_address(frame_pointer) orelse unreachable;
            const global_pointer_physical_address = kernel.bootstrap_virtual_address_space.translate_address(global_ptr_va) orelse unreachable;

            log.debug("Checking if instruction pointer is mapped to {}...", .{instruction_pointer_physical_address});
            assert(virtual_address_space.translate_address(instruction_pointer) != null);
            log.debug("Checking if frame pointer is mapped to {}...", .{frame_pointer_physical_address});
            assert(virtual_address_space.translate_address(frame_pointer) != null);
            log.debug("Checking if a global variable is mapped to {}...", .{global_pointer_physical_address});
            assert(virtual_address_space.translate_address(global_ptr_va) != null);

            assert(virtual_address_space.translate_address(virtual_address_space.arch.cr3.get_address().to_higher_half_virtual_address()) != null);
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
        .execute_disable = !general_flags.execute,
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
        assert(@sizeOf(u64) == @sizeOf(MemoryFlags));
    }
};

const address_mask: u64 = 0x0000_00ff_ffff_f000;

fn set_entry_in_address_bits(old_entry_value: u64, new_address: PhysicalAddress) u64 {
    if (kernel.config.safe_slow) {
        assert(x86_64.max_physical_address_bit == 40);
        assert(is_aligned(new_address.value, common.page_size));
    }

    const address_masked = new_address.value & address_mask;
    const old_entry_value_masked = old_entry_value & ~address_masked;
    const result = address_masked | old_entry_value_masked;

    return result;
}

inline fn get_address_from_entry_bits(entry_bits: u64) PhysicalAddress {
    const address = entry_bits & address_mask;
    if (kernel.config.safe_slow) {
        assert(common.max_physical_address_bit == 40);
        assert(is_aligned(address, common.page_size));
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
        assert(@sizeOf(@This()) == @sizeOf(u64));
        assert(@bitSizeOf(@This()) == @bitSizeOf(u64));
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
        assert(@sizeOf(@This()) == @sizeOf(u64));
        assert(@bitSizeOf(@This()) == @bitSizeOf(u64));
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
        assert(@sizeOf(@This()) == @sizeOf(u64));
        assert(@bitSizeOf(@This()) == @bitSizeOf(u64));
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
        assert(@sizeOf(@This()) == @sizeOf(u64));
        assert(@bitSizeOf(@This()) == @bitSizeOf(u64));
    }
};

const PML4Table = [512]PML4Entry;
const PDPTable = [512]PDPEntry;
const PDTable = [512]PDEntry;
const PTable = [512]PTEntry;

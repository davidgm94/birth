const common = @import("common");
const assert = common.assert;
const log = common.log.scoped(.Paging);

const privileged = @import("privileged");
const PhysicalAddress = privileged.PhysicalAddress;
const PhysicalMemoryRegion = privileged.PhysicalMemoryRegion;
const VirtualAddress = privileged.VirtualAddress;

const arch = @import("arch");
const cr3 = arch.x86_64.registers.cr3;

pub const Type = enum(u3) {
    device,

    const count = common.enum_count(Type);
};

var page_table_allocator = PageTableAllocator{};
const PageTableAllocator = struct {
    region: PhysicalMemoryRegion = .{
        .address = PhysicalAddress.temporary_invalid(),
        .size = 0,
    },
    allocated: usize = 0,

    pub fn allocate_one(allocator: *PageTableAllocator) !PhysicalAddress {
        if (allocator.region.size == 0 or allocator.allocated == allocator.region.size) {
            const physical_region = try arch.startup.bsp_address_space.allocate(arch.reasonable_page_size, arch.reasonable_page_size);
            allocator.* = .{
                .region = PhysicalMemoryRegion{
                    .address = physical_region.address,
                    .size = arch.reasonable_page_size,
                },
                .allocated = 0,
            };
        }

        const result = allocator.region.address.offset(allocator.allocated);
        allocator.allocated += 0x1000;

        return result;
    }
};
const flag_map = blk: {
    var result: [Type.count]MemoryFlags = undefined;
    result[@enumToInt(Type.device)] = .{
        .present = true,
        .read_write = true,
        .cache_disable = true,
        .global = true,
    };

    break :blk result;
};

const Error =
    error{
    unaligned_physical_address,
    unaligned_size,
};
const Indices = [common.enum_count(PageIndex)]u16;

// 0000_0000_0000_0000
//
pub fn get_pml4() *PML4Table {
    return cr3.read().get_address().to_higher_half_virtual_address().access(*PML4Table);
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

pub fn map_a_page(physical_address: PhysicalAddress, virtual_address: VirtualAddress, comptime page_size: u64) !void {
    log.debug("Mapping {} bytes from {} to {}", .{ page_size, physical_address, virtual_address });
    const indices = compute_indices(virtual_address);
    const pml4_table = get_pml4();
    const pml4_entry = &pml4_table[indices[@enumToInt(PageIndex.PML4)]];
    assert(pml4_entry.present);
    const pdp_table = unpack_address(pml4_entry).to_higher_half_virtual_address().access(*PDPTable);
    const pdp_entry = &pdp_table[indices[@enumToInt(PageIndex.PDP)]];
    const pd_table = blk: {
        const entry_physical_address = phys_blk: {
            if (pdp_entry.present) {
                break :phys_blk unpack_address(pdp_entry);
            } else {
                //pdp_entry.present = true;
                break :phys_blk try page_table_allocator.allocate_one();
            }
        };

        break :blk entry_physical_address.to_higher_half_virtual_address().access(*PDTable);
    };
    const pd_entry = &pd_table[indices[@enumToInt(PageIndex.PT)]];
    const p_table = blk: {
        const entry_physical_address = phys_blk: {
            if (pd_entry.present) {
                break :phys_blk unpack_address(pd_entry);
            } else {
                //pd_entry.present = true;
                break :phys_blk try page_table_allocator.allocate_one();
            }
        };

        break :blk entry_physical_address.to_higher_half_virtual_address().access(*PTable);
    };
    _ = p_table;
    //assert(pdp_entry.present);
    //const pd_table = unpack_address(pdp_entry).to_higher_half_virtual_address().access(*PDTable);
    //const pd_entry = pd_table[indices[@enumToInt(PageIndex.PD)]];
    @panic("todo map single page");
}

pub fn map(base_physical_address: PhysicalAddress, byte_count: u64, comptime memory_type: Type) !void {
    const flag = flag_map[@enumToInt(memory_type)];
    if (!common.is_aligned(base_physical_address.value, arch.page_size)) return Error.unaligned_physical_address;
    if (!common.is_aligned(byte_count, arch.page_size)) return Error.unaligned_size;
    const base_virtual_address = base_physical_address.to_higher_half_virtual_address();

    var physical_address = base_physical_address;
    var virtual_address = base_virtual_address;

    if (byte_count == arch.page_size) {
        try map_a_page(physical_address, virtual_address, arch.page_size);
    } else {
        @panic("todo fast batch map");
        //var top_virtual_address = base_virtual_address.offset(byte_count);
    }

    _ = flag;
    //const pml4_table = get_pml4();
    //const base_indices = compute_indices(virtual_address);
    //const top_indices = compute_indices(top_virtual_address);
    //for (base_indices) |base_index, i| {
    //const top_index = top_indices[i];
    //log.debug("[{}] Base: 0x{x}. Top: 0x{x}", .{ i, base_index, top_index });
    //}

    //while (virtual_address.value < top_virtual_address.value) : ({
    //physical_address.value += page_size;
    //virtual_address.value += page_size;
    //}) {}

    //_ = flag;
    @panic("todo map");
}

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

const PageIndex = enum(u3) {
    PML4 = 0,
    PDP = 1,
    PD = 2,
    PT = 3,
};

fn unpack_address(entry: anytype) PhysicalAddress {
    return PhysicalAddress.new(@as(u64, entry.address) << arch.page_shifter);
}

fn pack_address(physical_address: PhysicalAddress) u28 {
    return @intCast(u28, physical_address.value >> arch.page_shifter);
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

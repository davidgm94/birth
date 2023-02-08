const lib = @import("../lib.zig");
const assert = lib.assert;
const bootloader = @import("../bootloader.zig");

const privileged = @import("../privileged.zig");
const ACPI = privileged.ACPI;
const x86_64 = privileged.arch.x86_64;
const PhysicalAddress = x86_64.PhysicalAddress;
const VirtualAddress = x86_64.VirtualAddress;
const PhysicalMemoryRegion = x86_64.PhysicalMemoryRegion;
const VirtualMemoryRegion = x86_64.VirtualMemoryRegion;
const PhysicalAddressSpace = x86_64.PhysicalAddressSpace;
const VirtualAddressSpace = x86_64.VirtualAddressSpace;

inline fn segment(value: u32) u16 {
    return @intCast(u16, value & 0xffff0) >> 4;
}

inline fn offset(value: u32) u16 {
    return @truncate(u16, value & 0xf >> 0);
}

pub const Disk = extern struct {
    disk: lib.Disk,

    var buffer = [1]u8{0} ** (0x200 * 0x4);

    pub fn read(disk: *lib.Disk, sector_count: u64, sector_offset: u64, maybe_provided_buffer: ?[]u8) lib.Disk.ReadError!lib.Disk.ReadResult {
        const provided_buffer = maybe_provided_buffer orelse @panic("buffer was not provided");
        if (sector_count > lib.maxInt(u16)) @panic("too many sectors");

        const disk_buffer_address = @ptrToInt(&buffer);
        if (disk_buffer_address > lib.maxInt(u16)) @panic("address too high");

        var sectors_left = sector_count;
        while (sectors_left > 0) {
            const buffer_sectors = @divExact(buffer.len, disk.sector_size);
            const sectors_to_read = @intCast(u16, @min(sectors_left, buffer_sectors));
            defer sectors_left -= sectors_to_read;

            const lba_offset = sector_count - sectors_left;
            const lba = sector_offset + lba_offset;

            const dap = DAP{
                .sector_count = sectors_to_read,
                .offset = @intCast(u16, disk_buffer_address),
                .segment = 0,
                .lba = lba,
            };

            const dap_address = @ptrToInt(&dap);
            const dap_offset = offset(dap_address);
            const dap_segment = segment(dap_address);
            var registers = Registers{
                .eax = 0x4200,
                .edx = 0x80,
                .esi = dap_offset,
                .ds = dap_segment,
            };

            int(0x13, &registers, &registers);
            if (registers.eflags.flags.carry_flag) @panic("disk read failed");
            const provided_buffer_offset = lba_offset * disk.sector_size;
            const bytes_to_copy = sectors_to_read * disk.sector_size;
            const dst_slice = provided_buffer[@intCast(usize, provided_buffer_offset)..];
            const src_slice = buffer[0..bytes_to_copy];
            lib.copy(u8, dst_slice, src_slice);
        }

        const result = lib.Disk.ReadResult{
            .sector_count = sector_count,
            .buffer = provided_buffer.ptr,
        };

        return result;
    }

    pub fn write(disk: *lib.Disk, bytes: []const u8, sector_offset: u64, commit_memory_to_disk: bool) lib.Disk.WriteError!void {
        _ = disk;
        _ = bytes;
        _ = sector_offset;
        _ = commit_memory_to_disk;
        @panic("todo: disk write");
    }
};

extern fn int(number: u8, out_regs: *Registers, in_regs: *const Registers) callconv(.C) void;

const DAP = lib.PartitionTable.MBR.DAP;

extern fn hang() callconv(.C) noreturn;

const Registers = extern struct {
    gs: u16 = 0,
    fs: u16 = 0,
    es: u16 = 0,
    ds: u16 = 0,
    eflags: packed struct(u32) {
        flags: packed struct(u16) {
            carry_flag: bool = false,
            reserved: u1 = 1,
            parity_flag: bool = false,
            reserved1: u1 = 0,
            adjust_flag: bool = false,
            reserved2: u1 = 0,
            zero_flag: bool = false,
            sign_flag: bool = false,
            trap_flag: bool = false,
            interrupt_enabled_flag: bool = false,
            direction_flag: bool = false,
            overflow_flag: bool = false,
            io_privilege_level: u2 = 0,
            nested_task_flag: bool = false,
            mode_flag: bool = false,
        } = .{},
        extended: packed struct(u16) {
            resume_flag: bool = false,
            virtual_8086_mode: bool = false,
            alignment_smap_check: bool = false,
            virtual_interrupt_flag: bool = false,
            virtual_interrupt_pending: bool = false,
            cpuid: bool = false,
            reserved: u8 = 0,
            aes_key_schedule: bool = false,
            reserved1: bool = false,
        } = .{},
    } = .{},
    ebp: u32 = 0,
    edi: u32 = 0,
    esi: u32 = 0,
    edx: u32 = 0,
    ecx: u32 = 0,
    ebx: u32 = 0,
    eax: u32 = 0,
};

fn A20IsEnabled() bool {
    const address = 0x7dfe;
    const address_with_offset = address + 0x100000;
    if (@intToPtr(*volatile u16, address).* != @intToPtr(*volatile u16, address_with_offset).*) {
        return true;
    }

    @intToPtr(*volatile u16, address).* = ~(@intToPtr(*volatile u16, address).*);

    if (@intToPtr(*volatile u16, address).* != @intToPtr(*volatile u16, address_with_offset).*) {
        return true;
    }

    return false;
}

const A20Error = error{a20_not_enabled};

pub fn A20Enable() A20Error!void {
    if (!A20IsEnabled()) {
        return A20Error.a20_not_enabled;
    }
    // TODO:
}

pub const MemoryMapEntry = extern struct {
    region: PhysicalMemoryRegion(.global),
    type: Type,
    unused: u32 = 0,

    pub inline fn isLowMemory(entry: MemoryMapEntry) bool {
        return entry.region.address.value() < lib.mb;
    }

    pub inline fn isUsable(entry: MemoryMapEntry) bool {
        return entry.type == .usable and !entry.isLowMemory();
    }

    const Type = enum(u32) {
        usable = 1,
        reserved = 2,
        acpi_reclaimable = 3,
        acpi_nvs = 4,
        bad_memory = 5,
    };
};

var memory_map_entries: [max_memory_entry_count]MemoryMapEntry = undefined;
const max_memory_entry_count = 32;

pub const E820Iterator = extern struct {
    registers: Registers = .{},
    index: u32 = 0,

    pub fn next(iterator: *E820Iterator) ?struct { descriptor: MemoryMapEntry, index: usize } {
        var memory_map_entry: MemoryMapEntry = undefined;

        iterator.registers.eax = 0xe820;
        iterator.registers.ecx = 24;
        iterator.registers.edx = 0x534d4150;
        iterator.registers.edi = @ptrToInt(&memory_map_entry);

        int(0x15, &iterator.registers, &iterator.registers);

        if (!iterator.registers.eflags.flags.carry_flag and iterator.registers.ebx != 0) {
            const entry_index = iterator.index;
            iterator.index += 1;
            return .{ .index = entry_index, .descriptor = memory_map_entry };
        } else {
            return null;
        }
    }
};

pub fn getMemoryMapEntryCount() u32 {
    var entry_count: u32 = 0;
    var iterator = E820Iterator{};

    while (iterator.next()) |_| {
        entry_count += 1;
    }

    return entry_count;
}

const SuitableEntry = extern struct {
    region: PhysicalMemoryRegion(.local),
    index: u32,
};

pub fn findSuitableEntry(size: u32) ?SuitableEntry {
    var iterator = E820Iterator{};
    while (iterator.next()) |entry| {
        if (entry.isUsable() and entry.region.size > size) {
            return .{
                .region = entry.region,
                .index = iterator.index,
            };
        }
    }

    return null;
}

pub fn fetchMemoryEntries(memory_map: []bootloader.MemoryMapEntry) void {
    var iterator = E820Iterator{};
    while (iterator.next()) |entry| {
        memory_map[entry.index] = .{
            .region = entry.descriptor.region,
            .type = switch (entry.descriptor.type) {
                .usable => if (entry.descriptor.isUsable()) .usable else .reserved,
                .bad_memory => .bad_memory,
                else => .reserved,
            },
        };
    }

    if (iterator.index != memory_map.len) @panic("Memory map entries don't match");
}

const FindRSDPResult = union(enum) {
    descriptor1: *ACPI.RSDP.Descriptor1,
    descriptor2: *ACPI.RSDP.Descriptor2,
};

fn wrapSumBytes(bytes: []const u8) u8 {
    var result: u8 = 0;
    for (bytes) |byte| {
        result +%= byte;
    }
    return result;
}

pub fn getEBDAAddress() u32 {
    const expected_EBDA_base = 0x80000;
    const expected_EBDA_top = 0xa0000;

    const base = @as(u32, @intToPtr(*u16, 0x40e).*) << 4;

    if (base < expected_EBDA_base or base > expected_EBDA_top) {
        return expected_EBDA_base;
    } else {
        return base;
    }
}

pub fn findRSDP() ?u32 {
    const ebda_address = getEBDAAddress();
    const main_bios_area_base_address = 0xe0000;
    const RSDP_PTR = "RSD PTR ".*;

    const pointers = [2]u32{ ebda_address, main_bios_area_base_address };
    const limits = [2]u32{ ebda_address + @intCast(u32, @enumToInt(lib.SizeUnit.kilobyte)), @intCast(u32, @enumToInt(lib.SizeUnit.megabyte)) };
    for (pointers) |pointer, index| {
        var ptr = pointer;
        const limit = limits[index];

        while (ptr < limit) : (ptr += 16) {
            const rsdp_descriptor = @intToPtr(*ACPI.RSDP.Descriptor1, ptr);
            if (lib.equal(u8, &rsdp_descriptor.signature, &RSDP_PTR)) {
                switch (rsdp_descriptor.revision) {
                    0 => if (wrapSumBytes(lib.asBytes(rsdp_descriptor)) == 0) return @ptrToInt(rsdp_descriptor),
                    2 => {
                        const rsdp_descriptor2 = @fieldParentPtr(ACPI.RSDP.Descriptor2, "descriptor1", rsdp_descriptor);
                        if (wrapSumBytes(lib.asBytes(rsdp_descriptor2)) == 0) return @ptrToInt(rsdp_descriptor);
                    },
                    else => unreachable,
                }
            }
        }
    }

    return null;
}

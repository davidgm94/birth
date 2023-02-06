const lib = @import("../lib.zig");
const assert = lib.assert;
const log = lib.log;

pub const RSDP = extern struct {
    pub const Descriptor1 = extern struct {
        signature: [8]u8,
        checksum: u8,
        OEM_ID: [6]u8,
        revision: u8,
        RSDT_address: u32,

        pub fn findTable(rsdp: *RSDP.Descriptor1, table_signature: Signature) ?*const TableHeader {
            switch (rsdp.revision) {
                0 => {
                    const rsdt = @intToPtr(*TableHeader, rsdp.RSDT_address);
                    const entry_count = @divExact(rsdt.length - @sizeOf(TableHeader), @sizeOf(u32));
                    // TODO: this code is badly written
                    const entries = @intToPtr([*]const u32, rsdp.RSDT_address + @sizeOf(TableHeader))[0..entry_count];
                    for (entries) |entry| {
                        const table_header = @intToPtr(*const TableHeader, entry);
                        if (table_signature == table_header.signature) {
                            return table_header;
                        }
                    }

                    return null;
                },
                2 => {
                    @panic("todo: xsdt");
                },
                else => @panic("Unexpected value"),
            }
        }
    };

    pub const Descriptor2 = extern struct {
        descriptor1: Descriptor1,
        length: u32,
        XSDT_address: u64,
        extended_checksum: u8,
        reserved: [3]u8,
    };
};

const Signature = enum(u32) {
    APIC = @ptrCast(*align(1) const u32, "APIC").*,
    FACP = @ptrCast(*align(1) const u32, "FACP").*,
    HPET = @ptrCast(*align(1) const u32, "HPET").*,
    MCFG = @ptrCast(*align(1) const u32, "MCFG").*,
    WAET = @ptrCast(*align(1) const u32, "WAET").*,
};

pub const TableHeader = extern struct {
    signature: Signature,
    length: u32,
    revision: u8,
    checksum: u8,
    OEM_ID: [6]u8,
    OEM_table_ID: [8]u8,
    OEM_revision: u32,
    creator_ID: u32,
    creator_revision: u32,

    comptime {
        assert(@sizeOf(@This()) == 0x24);
    }
};

pub const MADT = extern struct {
    header: TableHeader,
    LAPIC_address: u32,
    flags: MADTFlags,

    pub const MADTFlags = packed struct(u32) {
        pcat_compatibility: bool,
        reserved: u31 = 0,
    };

    comptime {
        assert(@sizeOf(@This()) == 0x2c);
    }

    pub fn getIterator(madt: *const MADT) Iterator {
        return .{
            .madt = madt,
        };
    }

    pub fn getCPUCount(madt: *const MADT) u32 {
        var cpu_count: u32 = 0;
        var iterator = madt.getIterator();
        while (iterator.next()) |entry| {
            cpu_count += switch (entry.type) {
                .LAPIC => blk: {
                    const lapic_entry = @fieldParentPtr(LAPIC, "record", entry);
                    break :blk @boolToInt((lapic_entry.flags.enabled and !lapic_entry.flags.online_capable) or (lapic_entry.flags.online_capable and !lapic_entry.flags.enabled));
                },
                .x2APIC => @panic("x2apic not implemented"),
                else => continue,
            };
        }

        return cpu_count;
    }

    pub const Record = extern struct {
        type: Type,
        length: u8,

        pub const Type = enum(u8) {
            LAPIC = 0,
            IOAPIC = 1,
            IOAPIC_ISO = 2,
            IOAPIC_NMI_source = 3,
            LAPIC_NMI = 4,
            LAPIC_address_override = 5,
            x2APIC = 9,
        };
    };

    pub const Iterator = extern struct {
        madt: *const MADT,
        index: usize = 0,
        offset: usize = @sizeOf(MADT),

        pub fn next(iterator: *Iterator) ?*const Record {
            if (iterator.offset < iterator.madt.header.length) {
                const record = @intToPtr(*const Record, @ptrToInt(iterator.madt) + iterator.offset);
                iterator.offset += record.length;
                return record;
            }

            return null;
        }
    };

    pub const LAPIC = extern struct {
        record: Record,
        ACPI_processor_UID: u8,
        APIC_ID: u8,
        flags: Flags,

        const Flags = packed struct(u32) {
            enabled: bool,
            online_capable: bool,
            reserved: u30 = 0,
        };
    };
};

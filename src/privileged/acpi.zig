const lib = @import("lib");
const assert = lib.assert;
const log = lib.log;

pub const RSDP = extern struct {
    pub const Descriptor1 = extern struct {
        signature: [8]u8,
        checksum: u8,
        OEM_ID: [6]u8,
        revision: u8,
        RSDT_address: u32,

        comptime {
            assert(@sizeOf(Descriptor1) == 20);
        }

        const RSDPError = error{
            version_corrupted,
            table_not_found,
            xsdt_32_bit,
        };

        pub fn findTable(rsdp: *RSDP.Descriptor1, table_signature: Signature) !*align(1) const Header {
            switch (switch (rsdp.revision) {
                0 => false,
                2 => true,
                else => return RSDPError.version_corrupted,
            }) {
                inline else => |is_xsdt| {
                    if (is_xsdt and lib.cpu.arch == .x86) return RSDPError.xsdt_32_bit;

                    const root_table_address = switch (is_xsdt) {
                        false => rsdp.RSDT_address,
                        true => @fieldParentPtr(RSDP.Descriptor2, "descriptor1", rsdp).XSDT_address,
                    };

                    const root_table_header = @as(*align(1) Header, @ptrFromInt(root_table_address));
                    const EntryType = switch (is_xsdt) {
                        false => u32,
                        true => u64,
                    };

                    const entry_count = @divExact(root_table_header.length - @sizeOf(Header), @sizeOf(EntryType));
                    const entries = @as([*]align(1) const EntryType, @ptrFromInt(@intFromPtr(root_table_header) + @sizeOf(Header)))[0..entry_count];
                    for (entries) |entry| {
                        const table_header = @as(*align(1) const Header, @ptrFromInt(entry));
                        if (table_signature == table_header.signature) {
                            return table_header;
                        }
                    }

                    return RSDPError.table_not_found;
                },
            }
        }
    };

    pub const Descriptor2 = extern struct {
        descriptor1: Descriptor1,
        length: u32,
        XSDT_address: u64 align(4),
        cheksum: u8,
        reserved: [3]u8,

        comptime {
            assert(@alignOf(Descriptor1) == 4);
            assert(@alignOf(Descriptor2) == 4);
            assert(@sizeOf(Descriptor2) == 36);
        }
    };
};

const Signature = enum(u32) {
    APIC = @as(*align(1) const u32, @ptrCast("APIC")).*,
    FACP = @as(*align(1) const u32, @ptrCast("FACP")).*,
    HPET = @as(*align(1) const u32, @ptrCast("HPET")).*,
    MCFG = @as(*align(1) const u32, @ptrCast("MCFG")).*,
    WAET = @as(*align(1) const u32, @ptrCast("WAET")).*,
    BGRT = @as(*align(1) const u32, @ptrCast("BGRT")).*,
    _,
};

pub const Header = extern struct {
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
    header: Header,
    LAPIC_address: u32,
    flags: MADTFlags,

    pub const MADTFlags = packed struct(u32) {
        pcat_compatibility: bool,
        reserved: u31 = 0,
    };

    comptime {
        assert(@sizeOf(@This()) == 0x2c);
    }

    pub fn getIterator(madt: *align(1) const MADT) Iterator {
        return .{
            .madt = madt,
        };
    }

    pub fn getCPUCount(madt: *align(1) const MADT) u32 {
        var cpu_count: u32 = 0;
        var iterator = madt.getIterator();
        while (iterator.next()) |entry| {
            cpu_count += switch (entry.type) {
                .LAPIC => blk: {
                    const lapic_entry = @fieldParentPtr(LAPIC, "record", entry);
                    break :blk @intFromBool((lapic_entry.flags.enabled and !lapic_entry.flags.online_capable) or (lapic_entry.flags.online_capable and !lapic_entry.flags.enabled));
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

        const Type = enum(u8) {
            LAPIC = 0,
            IO_APIC = 1,
            ISO = 2,
            NMI_source = 3,
            LAPIC_NMI = 4,
            LAPIC_address_override = 5,
            IO_SAPIC = 6,
            LSAPIC = 7,
            platform_interrupt_sources = 8,
            x2APIC = 9,
            x2APIC_NMI = 0xa,
            GIC_CPU_interface = 0xb,
            GIC_distributor = 0xc,
            GIC_MSI_frame = 0xd,
            GIC_redistributor = 0xe,
            GIC_interrupt_translation_service = 0xf,
        };
    };

    pub const Iterator = extern struct {
        madt: *align(1) const MADT,
        index: usize = 0,
        offset: usize = @sizeOf(MADT),

        pub fn next(iterator: *Iterator) ?*const Record {
            if (iterator.offset < iterator.madt.header.length) {
                const record = @as(*const Record, @ptrFromInt(@intFromPtr(iterator.madt) + iterator.offset));
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

    const IO_APIC = extern struct {
        record: Record,
        IO_APIC_ID: u8,
        reserved: u8,
        IO_APIC_address: u32,
        global_system_interrupt_base: u32,

        comptime {
            assert(@sizeOf(@This()) == @sizeOf(u64) + @sizeOf(u32));
        }
    };

    const InterruptSourceOverride = extern struct {
        record: Record,
        bus: u8,
        source: u8,
        global_system_interrupt: u32 align(2),
        flags: u16 align(2),

        comptime {
            assert(@sizeOf(@This()) == @sizeOf(u64) + @sizeOf(u16));
        }
    };

    const LAPIC_NMI = extern struct {
        record: Record,
        ACPI_processor_UID: u8,
        flags: u16 align(1),
        LAPIC_lint: u8,

        comptime {
            assert(@sizeOf(@This()) == @sizeOf(u32) + @sizeOf(u16));
        }
    };
};

const MCFG = extern struct {
    header: Header,
    reserved: u64,

    fn getConfigurations(mcfg: *align(1) MCFG) []Configuration {
        const entry_count = (mcfg.header.length - @sizeOf(MCFG)) / @sizeOf(Configuration);
        const configuration_base = @intFromPtr(mcfg) + @sizeOf(MCFG);
        return @as([*]Configuration, @ptrFromInt(configuration_base))[0..entry_count];
    }

    comptime {
        assert(@sizeOf(MCFG) == @sizeOf(Header) + @sizeOf(u64));
        assert(@sizeOf(Configuration) == 0x10);
    }

    const Configuration = extern struct {
        base_address: u64,
        segment_group_number: u16,
        start_bus: u8,
        end_bus: u8,
        reserved: u32,
    };
};

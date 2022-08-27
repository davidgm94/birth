const std = @import("../common/std.zig");

const arch = @import("../kernel/arch/common.zig");
const DeviceManager = @import("../kernel/device_manager.zig");
const Drivers = @import("common.zig");
const crash = @import("../kernel/crash.zig");
const PhysicalAddress = @import("../kernel/physical_address.zig");
const interrupts = @import("../kernel/arch/x86_64/interrupts.zig");
const VirtualAddress = @import("../kernel/virtual_address.zig");
const VirtualAddressSpace = @import("../kernel/virtual_address_space.zig");
const x86_64 = @import("../kernel/arch/x86_64/common.zig");

const Allocator = std.Allocator;
const log = std.log.scoped(.ACPI);
const page_size = arch.page_size;
const panic = crash.panic;
const TODO = crash.TODO;

const Signature = enum(u32) {
    APIC = @ptrCast(*const u32, "APIC").*,
    FACP = @ptrCast(*const u32, "FACP").*,
    HPET = @ptrCast(*const u32, "HPET").*,
    MCFG = @ptrCast(*const u32, "MCFG").*,
    WAET = @ptrCast(*const u32, "WAET").*,
};

comptime {
    std.assert(std.cpu.arch == .x86_64);
}

/// ACPI initialization. We should have a page mapper ready before executing this function
pub fn init(device_manager: *DeviceManager, virtual_address_space: *VirtualAddressSpace, comptime driver_tree: ?[]const Drivers.Tree) !void {
    _ = device_manager;
    _ = driver_tree;
    const rsdp_physical_address = PhysicalAddress.new(x86_64.rsdp_physical_address);
    log.debug("RSDP: 0x{x}", .{rsdp_physical_address.value});
    const rsdp_physical_page = rsdp_physical_address.aligned_backward(page_size);
    virtual_address_space.map(rsdp_physical_page, rsdp_physical_page.to_higher_half_virtual_address(), VirtualAddressSpace.Flags.empty());
    const rsdp1 = rsdp_physical_address.access_kernel(*align(1) RSDP1);

    if (rsdp1.revision == 0) {
        log.debug("First version", .{});
        log.debug("RSDT: 0x{x}", .{rsdp1.RSDT_address});
        const rsdt_physical_address = PhysicalAddress.new(rsdp1.RSDT_address);
        const rsdt_physical_page = rsdt_physical_address.aligned_backward(page_size);
        virtual_address_space.map(rsdt_physical_page, rsdt_physical_page.to_higher_half_virtual_address(), VirtualAddressSpace.Flags.empty());
        log.debug("Mapped RSDT: 0x{x}", .{rsdt_physical_page.to_higher_half_virtual_address().value});
        const rsdt = rsdt_physical_address.access_kernel(*align(1) Header);
        log.debug("RSDT length: {}", .{rsdt.length});
        const rsdt_table_count = (rsdt.length - @sizeOf(Header)) / @sizeOf(u32);
        log.debug("RSDT table count: {}", .{rsdt_table_count});
        const tables = @intToPtr([*]align(1) u32, @ptrToInt(rsdt) + @sizeOf(Header))[0..rsdt_table_count];
        for (tables) |table_address| {
            log.debug("Table address: 0x{x}", .{table_address});
            const table_physical_address = PhysicalAddress.new(table_address);
            const table_physical_page = table_physical_address.aligned_backward(page_size);
            virtual_address_space.map(table_physical_page, table_physical_page.to_higher_half_virtual_address(), VirtualAddressSpace.Flags.empty());
            const header = table_physical_address.access_kernel(*align(1) Header);

            switch (header.signature) {
                .APIC => {
                    const madt = @ptrCast(*align(1) MADT, header);
                    log.debug("MADT: {}", .{madt});
                    log.debug("LAPIC address: 0x{x}", .{madt.LAPIC_address});

                    const madt_top = @ptrToInt(madt) + madt.header.length;
                    var offset = @ptrToInt(madt) + @sizeOf(MADT);

                    var processor_count: u64 = 0;
                    var iso_count: u64 = 0;
                    var entry_length: u64 = 0;

                    while (offset != madt_top) : (offset += entry_length) {
                        const entry_type = @intToPtr(*MADT.Type, offset).*;
                        entry_length = @intToPtr(*u8, offset + 1).*;
                        processor_count += @boolToInt(entry_type == .LAPIC);
                        iso_count += @boolToInt(entry_type == .ISO);
                    }

                    interrupts.iso = virtual_address_space.heap.allocator.alloc(interrupts.ISO, iso_count) catch @panic("iso");
                    var iso_i: u64 = 0;

                    offset = @ptrToInt(madt) + @sizeOf(MADT);

                    while (offset != madt_top) : (offset += entry_length) {
                        const entry_type = @intToPtr(*MADT.Type, offset).*;
                        entry_length = @intToPtr(*u8, offset + 1).*;

                        switch (entry_type) {
                            .LAPIC => {
                                const lapic = @intToPtr(*align(1) MADT.LAPIC, offset);
                                log.debug("LAPIC: {}", .{lapic});
                                std.assert(@sizeOf(MADT.LAPIC) == entry_length);
                            },
                            .IO_APIC => {
                                const ioapic = @intToPtr(*align(1) MADT.IO_APIC, offset);
                                log.debug("IO_APIC: {}", .{ioapic});
                                std.assert(@sizeOf(MADT.IO_APIC) == entry_length);
                                interrupts.ioapic.gsi = ioapic.global_system_interrupt_base;
                                interrupts.ioapic.address = PhysicalAddress.new(ioapic.IO_APIC_address);
                                virtual_address_space.map(interrupts.ioapic.address, interrupts.ioapic.address.to_higher_half_virtual_address(), .{ .write = true, .cache_disable = true });
                                interrupts.ioapic.id = ioapic.IO_APIC_ID;
                            },
                            .ISO => {
                                const iso = @intToPtr(*align(1) MADT.InterruptSourceOverride, offset);
                                log.debug("ISO: {}", .{iso});
                                std.assert(@sizeOf(MADT.InterruptSourceOverride) == entry_length);
                                const iso_ptr = &interrupts.iso[iso_i];
                                iso_i += 1;
                                iso_ptr.gsi = iso.global_system_interrupt;
                                iso_ptr.source_IRQ = iso.source;
                                iso_ptr.active_low = iso.flags & 2 != 0;
                                iso_ptr.level_triggered = iso.flags & 8 != 0;
                            },
                            .LAPIC_NMI => {
                                const lapic_nmi = @intToPtr(*align(1) MADT.LAPIC_NMI, offset);
                                log.debug("LAPIC_NMI: {}", .{lapic_nmi});
                                std.assert(@sizeOf(MADT.LAPIC_NMI) == entry_length);
                            },
                            else => panic("ni: {}", .{entry_type}),
                        }
                    }
                },
                else => {
                    log.debug("Ignored table: {s}", .{@tagName(header.signature)});
                },
            }
        }
    } else {
        std.assert(rsdp1.revision == 2);
        //const rsdp2 = @ptrCast(*RSDP2, rsdp1);
        log.debug("Second version", .{});
        TODO();
    }
}

const rsdt_signature = [4]u8{ 'R', 'S', 'D', 'T' };
pub fn check_valid_sdt(rsdt: *align(1) Header) void {
    log.debug("Header size: {}", .{@sizeOf(Header)});
    std.assert(@sizeOf(Header) == 36);
    if (rsdt.revision != 1) {
        @panic("bad revision");
    }
    if (!std.string_eq(&rsdt.signature, &rsdt_signature)) {
        @panic("bad signature");
    }
    if (rsdt.length >= 16384) {
        @panic("bad length");
    }
    if (checksum(@ptrCast([*]u8, rsdt)[0..rsdt.length]) != 0) {
        @panic("bad checksum");
    }
}

fn checksum(slice: []const u8) u8 {
    if (slice.len == 0) return 0;

    var total: u64 = 0;
    for (slice) |byte| {
        total += byte;
    }

    return @truncate(u8, total);
}

const RSDP1 = extern struct {
    signature: [8]u8,
    checksum: u8,
    OEM_ID: [6]u8,
    revision: u8,
    RSDT_address: u32,

    comptime {
        std.assert(@sizeOf(RSDP1) == 20);
    }
};

const RSDP2 = packed struct {
    rsdp1: RSDP1,
    length: u32,
    XSDT_address: u64,
    extended_checksum: u8,
    reserved: [3]u8,
};

const Header = extern struct {
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
        std.assert(@sizeOf(Header) == 36);
    }
};

const MADT = extern struct {
    header: Header,
    LAPIC_address: u32,
    flags: u32,

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
        Lx2APIC = 9,
        Lx2APIC_NMI = 0xa,
        GIC_CPU_interface = 0xb,
        GIC_distributor = 0xc,
        GIC_MSI_frame = 0xd,
        GIC_redistributor = 0xe,
        GIC_interrupt_translation_service = 0xf,
    };

    const LAPIC = struct {
        type: Type,
        length: u8,
        ACPI_processor_UID: u8,
        APIC_ID: u8,
        flags: u32,

        comptime {
            std.assert(@sizeOf(@This()) == @sizeOf(u64));
        }
    };

    const IO_APIC = extern struct {
        type: Type,
        length: u8,
        IO_APIC_ID: u8,
        reserved: u8,
        IO_APIC_address: u32,
        global_system_interrupt_base: u32,

        comptime {
            std.assert(@sizeOf(@This()) == @sizeOf(u64) + @sizeOf(u32));
        }
    };

    const InterruptSourceOverride = extern struct {
        type: Type,
        length: u8,
        bus: u8,
        source: u8,
        global_system_interrupt: u32 align(2),
        flags: u16 align(2),

        comptime {
            std.assert(@sizeOf(@This()) == @sizeOf(u64) + @sizeOf(u16));
        }
    };

    const LAPIC_NMI = extern struct {
        type: Type,
        length: u8,
        ACPI_processor_UID: u8,
        flags: u16 align(1),
        LAPIC_lint: u8,

        comptime {
            std.assert(@sizeOf(@This()) == @sizeOf(u32) + @sizeOf(u16));
        }
    };
};

const MCFG = packed struct {
    header: Header,
    reserved: u64,

    fn get_configurations(mcfg: *align(1) MCFG) []Configuration {
        const entry_count = (mcfg.header.length - @sizeOf(MCFG)) / @sizeOf(Configuration);
        const configuration_base = @ptrToInt(mcfg) + @sizeOf(MCFG);
        return @intToPtr([*]Configuration, configuration_base)[0..entry_count];
    }

    comptime {
        std.assert(@sizeOf(MCFG) == @sizeOf(Header) + @sizeOf(u64));
        std.assert(@sizeOf(Configuration) == 0x10);
    }

    const Configuration = packed struct {
        base_address: u64,
        segment_group_number: u16,
        start_bus: u8,
        end_bus: u8,
        reserved: u32,
    };
};

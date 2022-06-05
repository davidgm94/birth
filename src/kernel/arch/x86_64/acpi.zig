const kernel = @import("../../kernel.zig");
const log = kernel.log.scoped(.ACPI);
const TODO = kernel.TODO;
const Virtual = kernel.Virtual;
const Physical = kernel.Physical;
/// ACPI initialization. We should have a page mapper ready before executing this function
pub fn init(rsdp_physical_address: kernel.Physical.Address) void {
    var rsdp_physical_page = rsdp_physical_address;
    rsdp_physical_page.page_align_backward();
    kernel.address_space.map(rsdp_physical_page, rsdp_physical_page.identity_virtual_address());
    const rsdp1 = rsdp_physical_address.access_identity(*align(1) RSDP1);
    if (rsdp1.revision == 0) {
        log.debug("First version", .{});
        log.debug("RSDT: 0x{x}", .{rsdp1.RSDT_address});
        const rsdt_physical_address = Physical.Address.new(rsdp1.RSDT_address);
        var rsdt_physical_page = rsdt_physical_address;
        rsdt_physical_page.page_align_backward();
        kernel.address_space.map(rsdt_physical_page, rsdt_physical_page.identity_virtual_address());
        const rsdt = rsdt_physical_address.access_identity(*align(1) Header);
        log.debug("RSDT length: {}", .{rsdt.length});
        const rsdt_table_count = (rsdt.length - @sizeOf(Header)) / @sizeOf(u32);
        log.debug("RSDT table count: {}", .{rsdt_table_count});
        const tables = @intToPtr([*]align(1) u32, @ptrToInt(rsdt) + @sizeOf(Header))[0..rsdt_table_count];
        for (tables) |table_address| {
            log.debug("Table address: 0x{x}", .{table_address});
            const header = @intToPtr(*align(1) Header, table_address);
            log.debug("Table: {s}", .{header.signature});
        }
    } else {
        kernel.assert(@src(), rsdp1.revision == 2);
        //const rsdp2 = @ptrCast(*RSDP2, rsdp1);
        log.debug("Second version", .{});
        TODO(@src());
    }
}

const rsdt_signature = [4]u8{ 'R', 'S', 'D', 'T' };
pub fn check_valid_sdt(rsdt: *align(1) Header) void {
    log.debug("Header size: {}", .{@sizeOf(Header)});
    kernel.assert(@src(), @sizeOf(Header) == 36);
    if (rsdt.revision != 1) {
        @panic("bad revision");
    }
    if (!kernel.string_eq(&rsdt.signature, &rsdt_signature)) {
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
        kernel.assert_unsafe(@sizeOf(RSDP1) == 20);
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
    signature: [4]u8,
    length: u32,
    revision: u8,
    checksum: u8,
    OEM_ID: [6]u8,
    OEM_table_ID: [8]u8,
    OEM_revision: u32,
    creator_ID: u32,
    creator_revision: u32,
    comptime {
        kernel.assert_unsafe(@sizeOf(Header) == 36);
    }
};

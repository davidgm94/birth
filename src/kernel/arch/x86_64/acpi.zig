    /// ACPI initialization. We should have a page mapper ready before executing this function
    pub fn init(rsdp_address: u64) void {
        const rsdp1 = @intToPtr(*RSDP1, rsdp_address);
        if (rsdp1.revision == 0) {
            kernel.log("First version\n");
            const rsdt = @intToPtr(*Header, rsdp1.RSDT_address);
            const tables = @intToPtr([*]align(1) u32, rsdp1.RSDT_address + @sizeOf(Header))[0 .. (rsdt.length - @sizeOf(Header)) / @sizeOf(u32)];
            for (tables) |table_address| {
                kernel.logf("Table address: 0x{x}\n", .{table_address});
                const header = @intToPtr(*Header, table_address);
                kernel.logf("Table: {}\n", .{header});
            }
        } else {
            assert(rsdp1.revision == 2);
            //const rsdp2 = @ptrCast(*RSDP2, rsdp1);
            kernel.log("Second version\n");
            TODO();
        }
    }

    const RSDP1 = packed struct {
        signature: [8]u8,
        checksum: u8,
        OEM_ID: [6]u8,
        revision: u8,
        RSDT_address: u32,
    };

    const RSDP2 = packed struct {
        rsdp1: RSDP1,
        length: u32,
        XSDT_address: u64,
        extended_checksum: u8,
        reserved: [3]u8,
    };

    const Header = packed struct {
        signature: [4]u8,
        length: u32,
        revision: u8,
        checksum: u8,
        OEM_ID: [6]u8,
        OEM_table_ID: [8]u8,
        OEM_revision: u32,
        creator_ID: u32,
        creator_revision: u32,
    };

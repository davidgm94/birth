const lib = @import("lib");
const Allocator = lib.Allocator;
const assert = lib.assert;
const enumCount = lib.enumCount;
const log = lib.log.scoped(.capabilities);

const privileged = @import("privileged");
const PhysicalAddress = privileged.PhysicalAddress;
const PhysicalMemoryRegion = privileged.PhysicalMemoryRegion;
const rise = @import("rise");
const cpu = @import("cpu");

pub const Capability = extern struct {
    u: extern union {
        physical_address: Capability.PhysicalAddress,
    },
    rights: Rights,
    type: Type,

    pub const Type = enum {};
    pub const Rights = packed struct {
        reserved: u8 = 0,
    };
    pub const PhysicalAddress = extern struct {
        region: PhysicalMemoryRegion,
        address_space: u16,
        reserved: u16 = 0,
        reserved1: u32 = 0,
    };

    pub const RAM = Capability.PhysicalAddress;
};

pub const Static = enum {
    cpu,

    pub const count = lib.enumCount(@This());

    pub const Bitmap = @Type(.{
        .Struct = blk: {
            const full_bit_size = @max(@as(comptime_int, 1 << 3), @as(u8, @sizeOf(Static)) << 3);
            break :blk .{
                .layout = .Packed,
                .backing_integer = lib.IntType(.unsigned, full_bit_size),
                .fields = fields: {
                    var fields: []const lib.Type.StructField = &.{};
                    inline for (lib.enumFields(Static)) |static_field| {
                        fields = fields ++ [1]lib.Type.StructField{.{
                            .name = static_field.name,
                            .type = bool,
                            .default_value = null,
                            .is_comptime = false,
                            .alignment = 0,
                        }};
                    }

                    assert(Static.count > 0);
                    assert(@sizeOf(Static) > 0 or Static.count == 1);

                    const padding_type = lib.IntType(.unsigned, full_bit_size - Static.count);

                    fields = fields ++ [1]lib.Type.StructField{.{
                        .name = "reserved",
                        .type = padding_type,
                        .default_value = &0,
                        .is_comptime = false,
                        .alignment = 0,
                    }};
                    break :fields fields;
                },
                .decls = &.{},
                .is_tuple = false,
            };
        },
    });
};

pub const Dynamic = enum {
    io,
    // irq_table,
    // physical_memory,
    // device_memory,
    // ram,
    // cpu_memory,
    // vnode,
    // scheduler,

    pub const Map = extern struct {
        scheduler: Scheduler,
        page_tables: PageTables,
        io: IO,
    };
};

pub const IO = extern struct {
    debug: bool,
};

pub const Scheduler = extern struct {
    handle: ?*cpu.UserScheduler = null,
    memory: PhysicalMemoryRegion,
};

pub const PageTables = extern struct {
    root: PhysicalAddress = .null,
    first_block: ?*PageTableBlock = null,
    last_block: ?*PageTableBlock = null,

    comptime {
        assert(@sizeOf(PageTables) == 3 * @sizeOf(u64));
    }
};

comptime {
    assert(enumCount(Dynamic) + enumCount(Static) == enumCount(rise.capabilities.Type));
}

pub const Root = extern struct {
    static: Static.Bitmap,
    dynamic: Dynamic.Map,

    pub fn copy(root: *Root, other: *Root) void {
        other.static = root.static;
        // TODO:
        other.dynamic = root.dynamic;
    }

    pub inline fn hasPermissions(root: *const Root, comptime capability_type: rise.capabilities.Type, command: @field(rise.capabilities, @tagName(capability_type))) bool {
        return switch (capability_type) {
            // static capabilities
            .cpu => root.static.cpu,
            // dynamic capabilities
            else => |capability| switch (capability) {
                .io => switch (command) {
                    .log => root.dynamic.io.debug,
                },
                .cpu => unreachable,
            },
            // _ => return false,
        };
    }

    fn allocatePageTableNoCapacity(allocator: *Allocator, page_table_address: PhysicalAddress, flags: PageTableEntry.Flags) !*PageTableBlock {
        const page_table_block = try allocator.create(PageTableBlock);
        assert(page_table_block.index == 0);
        try page_table_block.addPageTableDescriptor(page_table_address, flags);

        return page_table_block;
    }

    pub fn addPageTable(root: *Root, allocator: *Allocator, page_table_address: PhysicalAddress, flags: PageTableEntry.Flags) !void {
        if (flags.type == cpu.arch.root_page_table_type) {
            root.dynamic.page_tables.root = page_table_address;
        } else if (root.dynamic.page_tables.last_block) |last_block| {
            assert(root.dynamic.page_tables.first_block != null);
            last_block.addPageTableDescriptor(page_table_address, flags) catch {
                const page_table_block = try allocatePageTableNoCapacity(allocator, page_table_address, flags);
                last_block.next = page_table_block;
                page_table_block.previous = last_block;
                root.dynamic.page_tables.last_block = page_table_block;
            };
        } else {
            assert(root.dynamic.page_tables.first_block == null);
            const page_table_block = try allocatePageTableNoCapacity(allocator, page_table_address, flags);
            root.dynamic.page_tables.first_block = page_table_block;
            root.dynamic.page_tables.last_block = page_table_block;
        }
    }
};

pub const RootPageTableEntry = extern struct {
    address: PhysicalAddress,
};

pub const PageTableBlock = extern struct {
    entries: [509]PageTableEntry,
    index: usize = 0,
    previous: ?*PageTableBlock = null,
    next: ?*PageTableBlock = null,

    comptime {
        assert(@sizeOf(PageTableBlock) == lib.arch.valid_page_sizes[0]);
    }

    pub const InsertionError = error{
        block_is_full,
    };

    fn addPageTableDescriptor(block: *PageTableBlock, page_table_entry_address: PhysicalAddress, flags: PageTableEntry.Flags) InsertionError!void {
        if (block.index < block.entries.len) {
            block.entries[block.index] = .{
                .address = @intCast(lib.FieldType(PageTableEntry, "address"), page_table_entry_address.value()),
                .flags = flags,
            };
            block.index += 1;
        } else return InsertionError.block_is_full;
    }
};

pub const PageTableEntry = packed struct(u64) {
    address: u48,
    flags: Flags,

    pub const Type = cpu.arch.PageTableEntry;

    pub const Flags = packed struct(u16) {
        type: Type,
        reserved: u14 = 0,
    };
};

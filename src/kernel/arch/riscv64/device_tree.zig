const std = @import("std");
const kernel = @import("../../kernel.zig");
const assert = kernel.assert;
const TODO = kernel.TODO;
const panicf = kernel.panicf;
const align_forward = kernel.align_forward;
const string_eq = kernel.string_eq;
const write = kernel.arch.write;
const log = kernel.log;
const read_big_endian = std.mem.readIntSliceBig;
const page_size = kernel.arch.page_size;
const MemoryRegion = kernel.MemoryRegion;
const logger = std.log.scoped(.init);

const DeviceTree = @This();
var result: DeviceTree.Result = undefined;

pub fn parse(fdt_address: u64) *DeviceTree.Result {
    logger.debug("Starting parsing the Flattened Device Tree...\n", .{});
    const dt_header = DeviceTree.Header.read(@intToPtr([*]const u8, fdt_address)[0..@sizeOf(DeviceTree.Header)]) catch unreachable;
    DeviceTree.MemoryReservationBlock.parse(dt_header, fdt_address);
    var dt_structure_block_parser: DeviceTree.StructureBlock.Parser = undefined;
    const returned_result = dt_structure_block_parser.parse(dt_header, fdt_address);
    logger.debug("Done parsing the FDT\n", .{});
    return returned_result;
}
const Header = struct {
    magic: u32,
    size: u32,
    device_tree_struct_offset: u32,
    device_tree_strings_offset: u32,
    rsvmap_memory_offset: u32,
    version: u32,
    last_comp_version: u32,
    boot_cpuid_physical_address: u32,
    device_tree_strings_size: u32,
    device_tree_struct_size: u32,

    const expected_magic = 0xd00dfeed;

    const ReadError = error{
        incorrect_magic,
    };

    fn read(bytes: []const u8) ReadError!DeviceTree.Header {
        var bytes_it = bytes;
        var device_tree_header: DeviceTree.Header = undefined;
        var device_tree_it_bytes = @ptrCast([*]u32, &device_tree_header);

        for (device_tree_it_bytes[0 .. @sizeOf(DeviceTree.Header) / @sizeOf(u32)]) |*device_tree_n| {
            device_tree_n.* = read_big_endian(u32, bytes_it);
            bytes_it.ptr += @sizeOf(u32);
            bytes_it.len -= @sizeOf(u32);
        }

        assert(@src(), device_tree_header.magic == expected_magic);

        return device_tree_header;
    }
};

const MemoryReservationBlock = struct {
    const Entry = struct {
        address: u64,
        size: u64,
    };

    fn parse(header: Header, header_offset: u64) void {
        const memory_reservation_block_offset = header.rsvmap_memory_offset;
        const block_address = header_offset + memory_reservation_block_offset;
        var block_it = @intToPtr([*]u8, block_address);

        var entry_count: u64 = 0;

        while (true) {
            var entry: Entry = undefined;
            entry.address = read_big_endian(u64, block_it[0..@sizeOf(u64)]);
            block_it += @sizeOf(u64);
            entry.size = read_big_endian(u64, block_it[0..@sizeOf(u64)]);
            block_it += @sizeOf(u64);

            if (entry.address == 0 and entry.size == 0) break;
            entry_count += 1;
        }

    }
};

const StructureBlock = struct {
    const Parser = struct {
        slice: []const u8,
        i: u64,
        header_address: u64,
        header: Header,

        fn parse(self: *@This(), header: Header, header_address: u64) *Result {
            self.header = header;
            self.header_address = header_address;
            const offset = self.header.device_tree_struct_offset;
            const size = self.header.device_tree_struct_size;
            const address = header_address + offset;

            self.slice = @intToPtr([*]u8, address)[0..size];
            self.i = 0;

            while (self.i < self.slice.len) {
                const main_token = self.parse_token();

                switch (main_token) {
                    .begin_node => {
                        const node_name = self.parse_begin_node();
                        assert(@src(), std.mem.eql(u8, node_name, ""));
                        var address_cells: u32 = 0;
                        var size_cells: u32 = 0;

                        while (true) {
                            const token = self.parse_token();

                            switch (token) {
                                .property => {
                                    const descriptor = self.parse_property_descriptor();
                                    const key = self.parse_string_in_string_table(descriptor);

                                    if (std.mem.eql(u8, key, "#address-cells")) {
                                        assert(@src(), descriptor.len == @sizeOf(u32));
                                        address_cells = self.read_int(u32);
                                    } else if (std.mem.eql(u8, key, "#size-cells")) {
                                        assert(@src(), descriptor.len == @sizeOf(u32));
                                        size_cells = self.read_int(u32);
                                    } else if (std.mem.eql(u8, key, "compatible")) {
                                        const str = self.parse_property_name(descriptor);
                                        _ = str;
                                    } else if (std.mem.eql(u8, key, "model")) {
                                        const str = self.parse_property_name(descriptor);
                                        _ = str;
                                    } else {
                                        TODO(@src());
                                    }
                                },
                                .begin_node => {
                                    const name = self.parse_begin_node();

                                    if (std.mem.eql(u8, name, "reserved-memory")) {
                                        while (true) {
                                            const node_token = self.parse_token();

                                            switch (node_token) {
                                                .property => {
                                                    const descriptor = self.parse_property_descriptor();
                                                    const key = self.parse_string_in_string_table(descriptor);

                                                    if (std.mem.eql(u8, key, "#address-cells")) {
                                                        assert(@src(), descriptor.len == @sizeOf(u32));
                                                        const value = self.read_int(u32);
                                                        _ = value;
                                                    } else if (std.mem.eql(u8, key, "#size-cells")) {
                                                        assert(@src(), descriptor.len == @sizeOf(u32));
                                                        const value = self.read_int(u32);
                                                        _ = value;
                                                    } else if (std.mem.eql(u8, key, "ranges")) {
                                                        assert(@src(), descriptor.len == 0);
                                                        const ranges_value = self.parse_string_in_string_table(descriptor);
                                                        _ = ranges_value;
                                                    } else {
                                                        TODO(@src());
                                                    }
                                                },
                                                .begin_node => {
                                                    const reserved_memory_name_node = self.parse_begin_node();

                                                    if (std.mem.startsWith(u8, reserved_memory_name_node, "mmode")) {
                                                        const at_index = std.mem.indexOf(u8, reserved_memory_name_node, "@") orelse @panic("expected address\n");
                                                        const address_str = reserved_memory_name_node[at_index + 1 ..];
                                                        const reserved_memory_address = std.fmt.parseInt(u64, address_str, 16) catch unreachable;
                                                        _ = reserved_memory_address;

                                                        while (true) {
                                                            const reserved_memory_node_token = self.parse_token();

                                                            switch (reserved_memory_node_token) {
                                                                .property => {
                                                                    const descriptor = self.parse_property_descriptor();
                                                                    const key = self.parse_string_in_string_table(descriptor);

                                                                    if (std.mem.eql(u8, key, "reg")) {
                                                                        const reserved_address = self.read_int(u64);
                                                                        const reserved_size = self.read_int(u64);
                                                                        result.reserved_memory_regions[result.reserved_memory_region_count].address = reserved_address;
                                                                        result.reserved_memory_regions[result.reserved_memory_region_count].size = reserved_size;
                                                                        result.reserved_memory_region_count += 1;
                                                                    } else {
                                                                        TODO(@src());
                                                                    }
                                                                },
                                                                .end_node => break,
                                                                else => panicf("Not implemented: {}\n", .{reserved_memory_node_token}),
                                                            }
                                                        }
                                                    } else {
                                                        TODO(@src());
                                                    }
                                                },
                                                .end_node => break,
                                                else => panicf("Not implemented: {}\n", .{node_token}),
                                            }
                                        }
                                    } else if (std.mem.startsWith(u8, name, "fw-cfg")) {
                                        self.skip_node();
                                        //while (true) {
                                        //const fw_cfg_token = self.parse_token();

                                        //switch (fw_cfg_token) {
                                        //.property => {
                                        //const descriptor = self.parse_property_descriptor();
                                        //logger.debug("Descriptor: {}\n", .{descriptor});
                                        //const key = self.parse_string_in_string_table(descriptor);
                                        //logger.debug("Property key: {s}\n", .{key});
                                        //TODO(@src());
                                        //},
                                        //else => panicf("FW cfg token is not implemented: {}\n", .{fw_cfg_token}),
                                        //}
                                        //}
                                    } else if (std.mem.startsWith(u8, name, "flash")) {
                                        self.skip_node();
                                    } else if (std.mem.eql(u8, name, "chosen")) {
                                        self.skip_node();
                                    } else if (std.mem.startsWith(u8, name, "memory")) {
                                        while (true) {
                                            const memory_token = self.parse_token();

                                            switch (memory_token) {
                                                .property => {
                                                    const descriptor = self.parse_property_descriptor();
                                                    const key = self.parse_string_in_string_table(descriptor);

                                                    if (string_eq(key, "device_type")) {
                                                        const device_type_value = self.parse_property_name(descriptor);
                                                        _ = device_type_value;
                                                    } else if (string_eq(key, "reg")) {
                                                        const i = self.i;
                                                        while (self.i < i + descriptor.len) {
                                                            const memory_address = self.read_int(u64);
                                                            const memory_size = self.read_int(u64);
                                                            result.memory_regions[result.memory_region_count].address = memory_address;
                                                            result.memory_regions[result.memory_region_count].size = memory_size;
                                                            result.memory_region_count += 1;
                                                        }
                                                    } else {
                                                        TODO(@src());
                                                    }
                                                },
                                                .end_node => break,
                                                else => panicf("Memory token is not implemented: {}\n", .{memory_token}),
                                            }
                                        }
                                    } else if (string_eq(name, "cpus")) {
                                        self.skip_node();
                                    } else if (string_eq(name, "soc")) {
                                        self.skip_node();
                                    } else {
                                        TODO(@src());
                                    }
                                },
                                .end_node => break,
                                else => panicf("Unexpected token: {}\n", .{token}),
                            }
                        }
                    },
                    .end => break,
                    else => panicf("Unexpected token: {}\n", .{main_token}),
                }
            }

            // Add the kernel memory region
            const kernel_address = kernel.arch.get_start();
            const kernel_end = kernel.arch.get_end();
            const kernel_size = kernel_end - kernel_address;
            assert(@src(), kernel_address & (page_size - 1) == 0);
            assert(@src(), kernel_end & (page_size - 1) == 0);
            result.reserved_memory_regions[result.reserved_memory_region_count].address = kernel_address;
            result.reserved_memory_regions[result.reserved_memory_region_count].size = kernel_size;
            result.reserved_memory_region_count += 1;

            // Add the FDT memory region
            result.reserved_memory_regions[result.reserved_memory_region_count].address = header_address;
            result.reserved_memory_regions[result.reserved_memory_region_count].size = align_forward(header.size, page_size);
            result.reserved_memory_region_count += 1;

            result.address = header_address;

            return &result;
        }

        fn parse_property_name(self: *@This(), descriptor: Property.Descriptor) []const u8 {
            const property_value = self.slice[self.i .. self.i + descriptor.len];
            self.i = align_to_u32(self.i + descriptor.len);
            return property_value;
        }

        //fn parse_properly_encoded_array(self: *@This(), descriptor: Property.Descriptor) []const u8 {
        //}

        fn skip_node(self: *@This()) void {
            while (true) {
                const skip_token = self.parse_token();
                switch (skip_token) {
                    .begin_node => {
                        self.skip_cstr();
                        self.skip_node();
                    },
                    .property => {
                        const len = self.read_int(u32);
                        self.i = align_to_u32(self.i + @sizeOf(u32) + len);
                    },
                    .end_node => {
                        break;
                    },
                    else => panicf("token unimplemented: {}\n", .{skip_token}),
                }
            }
        }

        fn skip_cstr(self: *@This()) void {
            const len = std.mem.len(@ptrCast([*:0]const u8, self.slice[self.i..].ptr));
            self.i = align_to_u32(self.i + len + 1);
        }

        fn parse_begin_node(self: *@This()) []const u8 {
            const node_name = self.read_cstr_advancing_it();
            self.i = align_to_u32(self.i);
            return node_name;
        }

        fn parse_property_descriptor(self: *@This()) Property.Descriptor {
            return Property.Descriptor{
                .len = self.read_int(u32),
                .name_offset = self.read_int(u32),
            };
        }

        fn parse_string_in_string_table(self: *@This(), descriptor: Property.Descriptor) []const u8 {
            const strings_offset = self.header.device_tree_strings_offset;
            const string_offset = self.header_address + strings_offset + descriptor.name_offset;
            const property_key_cstr = @intToPtr([*:0]u8, string_offset);
            const str = property_key_cstr[0..std.mem.len(property_key_cstr)];
            return str;
        }

        fn read_cstr_advancing_it(self: *@This()) []const u8 {
            const cstr_len = std.mem.len(@ptrCast([*:0]const u8, self.slice[self.i..].ptr));
            const cstr = self.slice[self.i .. self.i + cstr_len];
            self.i += cstr_len + 1;
            return cstr;
        }

        fn parse_token(self: *@This()) Token {
            assert(@src(), self.i & 0b11 == 0);
            const token_int = self.read_int(u32);
            //logger.debug("Trying to cast possible valid token {} into an enum\n", .{token_int});
            const token = @intToEnum(Token, token_int);
            return token;
        }

        fn read_int(self: *@This(), comptime Int: type) Int {
            const int = read_big_endian(Int, self.slice[self.i..]);
            self.i += @sizeOf(Int);
            return int;
        }

        const Token = enum(u32) {
            begin_node = 1,
            end_node = 2,
            property = 3,
            nop = 4,
            end = 9,
        };

        const Property = struct {
            const Descriptor = struct {
                len: u32,
                name_offset: u32,
            };
        };
    };

    inline fn align_to_u32(i: u64) u64 {
        return align_forward(i, @sizeOf(u32));
    }
};

pub const Result = struct {
    memory_regions: [1024]MemoryRegion,
    memory_region_count: u64,
    reserved_memory_regions: [64]MemoryRegion,
    reserved_memory_region_count: u64,
    address: u64,
};

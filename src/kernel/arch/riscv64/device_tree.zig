const std = @import("std");
const kernel = @import("../../kernel.zig");
const assert = kernel.assert;
const TODO = kernel.TODO;
const align_forward = kernel.align_forward;
const string_eq = kernel.string_eq;
const starts_with = kernel.string_starts_with;
const read_big_endian = std.mem.readIntSliceBig;
const page_size = kernel.arch.page_size;
const Memory = kernel.Memory;

const print = kernel.arch.early_print;
const write = kernel.arch.early_write;

const DeviceTree = @This();
var result: DeviceTree.Result = undefined;
const soft_separator = "----------------------------------------------------------------\n";
const hard_separator = "================================================================\n";

pub fn parse(fdt_address: u64) *DeviceTree.Result {
    write(hard_separator);
    defer write(hard_separator);
    print("Starting parsing the Flattened Device Tree...\n", .{});
    const dt_header = DeviceTree.Header.read(@intToPtr([*]const u8, fdt_address)[0..@sizeOf(DeviceTree.Header)]) catch unreachable;
    DeviceTree.MemoryReservationBlock.parse(dt_header, fdt_address);
    var dt_structure_block_parser: DeviceTree.StructureBlock.Parser = undefined;
    const returned_result = dt_structure_block_parser.parse(dt_header, fdt_address);
    print("Done parsing the FDT\n", .{});
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
            print("Entry (0x{x}, 0x{x})\n", .{ entry.address, entry.size });
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

            var address_cells: u32 = 0;
            var size_cells: u32 = 0;

            while (true) {
                const main_token: Token = self.parse_token();
                if (main_token == .end) break;
                assert(@src(), self.i < self.slice.len);
                assert(@src(), main_token == .begin_node);

                const node_name = self.parse_begin_node();
                assert(@src(), string_eq(node_name, ""));

                while (true) {
                    const token = self.parse_token();

                    switch (token) {
                        .property => {
                            const descriptor = self.parse_property_value_descriptor();
                            const key = self.parse_string_in_string_table(descriptor);
                            print("{s}: ", .{key});

                            if (string_eq(key, "#address-cells")) {
                                assert(@src(), descriptor.len == @sizeOf(u32));
                                address_cells = self.parse_int(u32);
                                print("{}\n", .{address_cells});
                            } else if (string_eq(key, "#size-cells")) {
                                assert(@src(), descriptor.len == @sizeOf(u32));
                                size_cells = self.parse_int(u32);
                                print("{}\n", .{size_cells});
                            } else if (string_eq(key, "compatible")) {
                                const value = self.parse_property_name(descriptor);
                                print("{s}\n", .{value});
                            } else if (string_eq(key, "model")) {
                                const value = self.parse_property_name(descriptor);
                                print("{s}\n", .{value});
                            } else {
                                TODO(@src());
                            }
                        },
                        .begin_node => {
                            self.parse_node(1, address_cells, size_cells);

                            //if (string_eq(name, "reserved-memory")) {
                            //while (true) {
                            //const node_token = self.parse_token();

                            //switch (node_token) {
                            //.property => {
                            //const descriptor = self.parse_property_value_descriptor();
                            //const key = self.parse_string_in_string_table(descriptor);

                            //if (string_eq(key, "#address-cells")) {
                            //assert(@src(), descriptor.len == @sizeOf(u32));
                            //const value = self.parse_int(u32);
                            //_ = value;
                            //} else if (string_eq(key, "#size-cells")) {
                            //assert(@src(), descriptor.len == @sizeOf(u32));
                            //const value = self.parse_int(u32);
                            //_ = value;
                            //} else if (string_eq(key, "ranges")) {
                            //assert(@src(), descriptor.len == 0);
                            //const ranges_value = self.parse_string_in_string_table(descriptor);
                            //_ = ranges_value;
                            //} else {
                            //TODO(@src());
                            //}
                            //},
                            //.begin_node => {
                            //const reserved_memory_name_node = self.parse_begin_node();

                            //if (std.mem.startsWith(u8, reserved_memory_name_node, "mmode")) {
                            //const at_index = std.mem.indexOf(u8, reserved_memory_name_node, "@") orelse @panic("expected address\n");
                            //const address_str = reserved_memory_name_node[at_index + 1 ..];
                            //const reserved_memory_address = std.fmt.parseInt(u64, address_str, 16) catch unreachable;
                            //_ = reserved_memory_address;

                            //while (true) {
                            //const reserved_memory_node_token = self.parse_token();

                            //switch (reserved_memory_node_token) {
                            //.property => {
                            //const descriptor = self.parse_property_value_descriptor();
                            //const key = self.parse_string_in_string_table(descriptor);

                            //if (string_eq(key, "reg")) {
                            //const reserved_address = self.parse_int(u64);
                            //const reserved_size = self.parse_int(u64);
                            //result.reserved_memory_regions[result.reserved_memory_region_count].address = reserved_address;
                            //result.reserved_memory_regions[result.reserved_memory_region_count].size = reserved_size;
                            //result.reserved_memory_region_count += 1;
                            //} else {
                            //TODO(@src());
                            //}
                            //},
                            //.end_node => break,
                            //else => kernel.panic("Not implemented: {}\n", .{reserved_memory_node_token}),
                            //}
                            //}
                            //} else {
                            //TODO(@src());
                            //}
                            //},
                            //.end_node => break,
                            //else => kernel.panic("Not implemented: {}\n", .{node_token}),
                            //}
                            //}
                            //} else if (std.mem.startsWith(u8, name, "fw-cfg")) {
                            //self.skip_node();
                            ////while (true) {
                            ////const fw_cfg_token = self.parse_token();

                            ////switch (fw_cfg_token) {
                            ////.property => {
                            ////const descriptor = self.parse_property_value_descriptor();
                            ////logger.debug("Descriptor: {}\n", .{descriptor});
                            ////const key = self.parse_string_in_string_table(descriptor);
                            ////logger.debug("Property key: {s}\n", .{key});
                            ////TODO(@src());
                            ////},
                            ////else => kernel.panic("FW cfg token is not implemented: {}\n", .{fw_cfg_token}),
                            ////}
                            ////}
                            //} else if (std.mem.startsWith(u8, name, "flash")) {
                            //self.skip_node();
                            //} else if (string_eq(name, "chosen")) {
                            //self.skip_node();
                            //} else if (std.mem.startsWith(u8, name, "memory")) {
                            //while (true) {
                            //const memory_token = self.parse_token();

                            //switch (memory_token) {
                            //.property => {
                            //const descriptor = self.parse_property_value_descriptor();
                            //const key = self.parse_string_in_string_table(descriptor);

                            //if (string_eq(key, "device_type")) {
                            //const device_type_value = self.parse_property_name(descriptor);
                            //_ = device_type_value;
                            //} else if (string_eq(key, "reg")) {
                            //const i = self.i;
                            //while (self.i < i + descriptor.len) {
                            //const memory_address = self.parse_int(u64);
                            //const memory_size = self.parse_int(u64);
                            //result.memory_regions[result.memory_region_count].address = memory_address;
                            //result.memory_regions[result.memory_region_count].size = memory_size;
                            //result.memory_region_count += 1;
                            //}
                            //} else {
                            //TODO(@src());
                            //}
                            //},
                            //.end_node => break,
                            //else => kernel.panic("Memory token is not implemented: {}\n", .{memory_token}),
                            //}
                            //}
                            //} else if (string_eq(name, "cpus")) {
                            //self.skip_node();
                            //} else if (string_eq(name, "soc")) {
                            //self.skip_node();
                            //} else {
                            //TODO(@src());
                            //}
                        },
                        .end_node => break,
                        else => kernel.panic("Unexpected token: {}\n", .{token}),
                    }
                }
            }

            // Add the kernel memory region
            const kernel_address = kernel.bounds.get_start();
            const kernel_end = kernel.bounds.get_end();
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

        fn parse_node(self: *@This(), identation: u32, parent_address_cells: u32, parent_size_cells: u32) void {
            const node_name = self.parse_begin_node();
            print_ident(identation, "* {s}:\n", .{node_name});

            const attribute_identation = identation + 1;
            _ = attribute_identation;

            var address_cells: u32 = parent_address_cells;
            var size_cells: u32 = parent_size_cells;

            while (true) {
                const token = self.parse_token();

                switch (token) {
                    .property => {
                        const property_value_descriptor = self.parse_property_value_descriptor();
                        const property_name = self.parse_string_in_string_table(property_value_descriptor);

                        print_ident(attribute_identation, "{s}: ", .{property_name});
                        // First check the standard ones
                        if (string_eq(property_name, "compatible")) {
                            const value = self.parse_property_name(property_value_descriptor);
                            print("{s}", .{value});
                        } else if (string_eq(property_name, "model")) {
                            TODO(@src());
                        } else if (string_eq(property_name, "phandle")) {
                            assert(@src(), property_value_descriptor.len == @sizeOf(u32));
                            const value = self.parse_int(u32);
                            print("{}", .{value});
                        } else if (string_eq(property_name, "status")) {
                            const value = self.parse_property_name(property_value_descriptor);
                            print("{s}", .{value});
                        } else if (string_eq(property_name, "#address-cells")) {
                            assert(@src(), property_value_descriptor.len == @sizeOf(u32));
                            address_cells = self.parse_int(u32);
                            print("{}", .{address_cells});
                        } else if (string_eq(property_name, "#size-cells")) {
                            assert(@src(), property_value_descriptor.len == @sizeOf(u32));
                            size_cells = self.parse_int(u32);
                            print_ident(attribute_identation, "{}", .{size_cells});
                        } else if (string_eq(property_name, "reg")) {
                            const address_byte_count = address_cells * @sizeOf(u32);
                            const size_byte_count = size_cells * @sizeOf(u32);
                            const pair_byte_count = address_byte_count + size_byte_count;
                            const pair_count = property_value_descriptor.len / pair_byte_count;
                            var pair_i: u64 = 0;
                            while (pair_i < pair_count) : (pair_i += 1) {
                                write("(");

                                switch (address_byte_count) {
                                    @sizeOf(u32) => {
                                        const value = self.parse_int(u32);
                                        print("0x{x}", .{value});
                                    },
                                    @sizeOf(u64) => {
                                        const value = self.parse_int(u64);
                                        print("0x{x}", .{value});
                                    },
                                    0 => {},
                                    else => unreachable,
                                }

                                write(" , ");

                                switch (size_byte_count) {
                                    @sizeOf(u64) => {
                                        const value = self.parse_int(u64);
                                        print("0x{x}", .{value});
                                    },
                                    0 => {},
                                    else => unreachable,
                                }

                                write("), ");
                            }
                        } else if (string_eq(property_name, "virtual-reg")) {
                            TODO(@src());
                        } else if (string_eq(property_name, "ranges")) {
                            if (property_value_descriptor.len != 0) {
                                self.i += property_value_descriptor.len;
                                write("TODO");
                                //write("\n");
                                //for (self.slice[i .. i + 100]) |b, index| {
                                //print("[{}] {c}\n", .{ index, b });
                                //}
                                //TODO(@src());
                            } else {
                                write("empty");
                                //self.i += 1;
                            }
                        } else if (string_eq(property_name, "dma-ranges")) {
                            TODO(@src());
                        } else if (string_eq(property_name, "dma-coherent")) {
                            assert(@src(), property_value_descriptor.len == 0);
                        } else {
                            //Non-standard ones
                            if (starts_with(node_name, "flash")) {
                                if (string_eq(property_name, "bank-width")) {
                                    assert(@src(), property_value_descriptor.len == @sizeOf(u32));
                                    const bank_width = self.parse_int(u32);
                                    print("{}", .{bank_width});
                                } else {
                                    TODO(@src());
                                }
                            } else if (string_eq(node_name, "chosen")) {
                                // Chosen is a standard node
                                if (string_eq(property_name, "bootargs")) {
                                    const value = self.parse_property_name(property_value_descriptor);
                                    print("{s}", .{value});
                                } else if (string_eq(property_name, "stdout-path")) {
                                    const value = self.parse_property_name(property_value_descriptor);
                                    print("{s}", .{value});
                                } else {
                                    print("Property unknown: {s}", .{property_name});
                                    TODO(@src());
                                }
                            } else if (starts_with(node_name, "memory")) {
                                if (string_eq(property_name, "device_type")) {
                                    const value = self.parse_property_name(property_value_descriptor);
                                    print("{s}", .{value});
                                } else {
                                    TODO(@src());
                                }
                            } else if (string_eq(node_name, "cpus")) {
                                if (string_eq(property_name, "timebase-frequency")) {
                                    self.parse_and_print_freq(property_value_descriptor);
                                } else {
                                    TODO(@src());
                                }
                            } else if (starts_with(node_name, "cpu@")) {
                                if (string_eq(property_name, "device_type")) {
                                    const value = self.parse_property_name(property_value_descriptor);
                                    print("{s}", .{value});
                                } else if (string_eq(property_name, "riscv,isa")) {
                                    const value = self.parse_property_name(property_value_descriptor);
                                    print("{s}", .{value});
                                } else if (string_eq(property_name, "mmu-type")) {
                                    const value = self.parse_property_name(property_value_descriptor);
                                    print("{s}", .{value});
                                } else {
                                    TODO(@src());
                                }
                            } else if (string_eq(node_name, "interrupt-controller")) {
                                if (string_eq(property_name, "#interrupt-cells")) {
                                    const value = self.parse_int(u32);
                                    print("{}", .{value});
                                } else if (string_eq(property_name, "interrupt-controller")) {
                                    assert(@src(), property_value_descriptor.len == 0);
                                } else {
                                    TODO(@src());
                                }
                            } else if (starts_with(node_name, "core")) {
                                if (string_eq(property_name, "cpu")) {
                                    const value = self.parse_int(u32);
                                    print("{}\n", .{value});
                                } else {
                                    TODO(@src());
                                }
                            } else if (starts_with(node_name, "rtc@") or starts_with(node_name, "uart@")) {
                                if (string_eq(property_name, "interrupts")) {
                                    const value = self.parse_int(u32);
                                    print("{}", .{value});
                                } else if (string_eq(property_name, "interrupt-parent")) {
                                    const value = self.parse_int(u32);
                                    print("{}", .{value});
                                    //const value = property_value_descriptor.len;
                                    //print("{}", .{value});
                                    //TODO(@src());
                                } else if (string_eq(property_name, "clock-frequency")) {
                                    self.parse_and_print_freq(property_value_descriptor);
                                } else {
                                    TODO(@src());
                                }
                            } else if (string_eq(node_name, "poweroff") or string_eq(node_name, "reboot")) {
                                if (string_eq(property_name, "value")) {
                                    const value = self.parse_int(u32);
                                    print("{}", .{value});
                                } else if (string_eq(property_name, "offset")) {
                                    const value = self.parse_int(u32);
                                    print("{}", .{value});
                                } else if (string_eq(property_name, "regmap")) {
                                    const value = self.parse_int(u32);
                                    print("{}", .{value});
                                } else {
                                    TODO(@src());
                                }
                            } else if (starts_with(node_name, "pci@")) {
                                if (string_eq(property_name, "interrupt-map-mask")) {
                                    const value = self.parse_int(u64);
                                    const value2 = self.parse_int(u64);
                                    print("0x{x}, 0x{x}", .{ value, value2 });
                                } else if (string_eq(property_name, "interrupt-map")) {
                                    // TODO
                                    self.i += property_value_descriptor.len;
                                    //var i: u32 = 0;
                                    //while (i < byte_count) : (i += @sizeOf(u64)) {
                                    //_ = self.parse_int(u64);
                                    //}
                                    write("TODO");
                                } else if (string_eq(property_name, "bus-range")) {
                                    const value = self.parse_int(u64);
                                    print("{}", .{value});
                                } else if (string_eq(property_name, "linux,pci-domain")) {
                                    const value = self.parse_int(u32);
                                    print("{}", .{value});
                                } else if (string_eq(property_name, "device_type")) {
                                    const value = self.parse_property_name(property_value_descriptor);
                                    print("{s}", .{value});
                                } else if (string_eq(property_name, "#interrupt-cells")) {
                                    const value = self.parse_property_name(property_value_descriptor);
                                    print("{s}", .{value});
                                } else {
                                    TODO(@src());
                                }
                            } else if (starts_with(node_name, "virtio_mmio@")) {
                                if (string_eq(property_name, "interrupts")) {
                                    const value = self.parse_int(u32);
                                    print("{}", .{value});
                                } else if (string_eq(property_name, "interrupt-parent")) {
                                    const value = self.parse_int(u32);
                                    print("{}", .{value});
                                } else {
                                    TODO(@src());
                                }
                            } else if (starts_with(node_name, "plic@")) {
                                if (string_eq(property_name, "riscv,ndev")) {
                                    const value = self.parse_int(u32);
                                    print("{}", .{value});
                                } else if (string_eq(property_name, "interrupts-extended")) {
                                    //const value = property_value_descriptor.len;
                                    const value1 = self.parse_int(u32);
                                    const value2 = self.parse_int(u32);
                                    const value3 = self.parse_int(u32);
                                    const value4 = self.parse_int(u32);
                                    print("{}, {}, {}, {} ", .{ value1, value2, value3, value4 });
                                    write("TODO");
                                } else if (string_eq(property_name, "interrupt-controller")) {
                                    assert(@src(), property_value_descriptor.len == 0);
                                } else if (string_eq(property_name, "#interrupt-cells")) {
                                    const value = self.parse_property_name(property_value_descriptor);
                                    print("{s}", .{value});
                                } else {
                                    TODO(@src());
                                }
                            } else if (starts_with(node_name, "clint@")) {
                                if (string_eq(property_name, "interrupts-extended")) {
                                    //const value = property_value_descriptor.len;
                                    const value1 = self.parse_int(u32);
                                    const value2 = self.parse_int(u32);
                                    const value3 = self.parse_int(u32);
                                    const value4 = self.parse_int(u32);
                                    print("{}, {}, {}, {} ", .{ value1, value2, value3, value4 });
                                    write("TODO");
                                } else {
                                    TODO(@src());
                                }
                            } else {
                                TODO(@src());
                            }
                        }

                        write("\n");
                    },
                    .begin_node => self.parse_node(attribute_identation + 1, address_cells, size_cells),
                    .end_node => break,
                    else => kernel.panic("NI: {s}\n", .{@tagName(token)}),
                }
            }
        }

        fn parse_and_print_freq(self: *@This(), property_value_descriptor: Property.Descriptor) void {
            switch (property_value_descriptor.len) {
                @sizeOf(u32) => {
                    const value = self.parse_int(u32);
                    print("{} Hz", .{value});
                },
                @sizeOf(u64) => {
                    TODO(@src());
                },
                else => unreachable,
            }
        }

        fn print_ident(identation: u32, comptime format: []const u8, args: anytype) void {
            var ident_it: u32 = 0;
            while (ident_it < identation) : (ident_it += 1) {
                write("    ");
            }

            print(format, args);
        }

        fn write_ident(identation: u32, bytes: []const u8) void {
            var ident_it: u32 = 0;
            while (ident_it < identation) : (ident_it += 1) {
                write("    ");
            }
            write(bytes);
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
                        const len = self.parse_int(u32);
                        self.i = align_to_u32(self.i + @sizeOf(u32) + len);
                    },
                    .end_node => {
                        break;
                    },
                    else => kernel.panic("token unimplemented: {}\n", .{skip_token}),
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

        fn parse_property_value_descriptor(self: *@This()) Property.Descriptor {
            return Property.Descriptor{
                .len = self.parse_int(u32),
                .name_offset = self.parse_int(u32),
            };
        }

        fn parse_string_in_string_table(self: *@This(), descriptor: Property.Descriptor) []const u8 {
            const strings_offset = self.header.device_tree_strings_offset;
            const string_offset = self.header_address + strings_offset + descriptor.name_offset;
            const property_key_cstr = @intToPtr([*:0]u8, string_offset);
            const value = property_key_cstr[0..std.mem.len(property_key_cstr)];
            return value;
        }

        fn read_cstr_advancing_it(self: *@This()) []const u8 {
            const cstr_len = std.mem.len(@ptrCast([*:0]const u8, self.slice[self.i..].ptr));
            const cstr = self.slice[self.i .. self.i + cstr_len];
            self.i += cstr_len + 1;
            return cstr;
        }

        fn parse_token(self: *@This()) Token {
            assert(@src(), self.i & 0b11 == 0);
            const token_int = self.parse_int(u32);
            //logger.debug("Trying to cast possible valid token {} into an enum\n", .{token_int});
            const token = @intToEnum(Token, token_int);
            return token;
        }

        fn parse_int(self: *@This(), comptime Int: type) Int {
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
            name: []const u8,
            value: union(enum) {
                empty: void,
                int32: u32,
                int64: u64,
                string: []const u8,
                phandle: u32,
                string_list: []const u8, // We store stringlist in a single string
            },
            const Descriptor = struct {
                len: u32,
                name_offset: u32,
            };
        };

        const Types = enum(u32) {
            empty = 0,
            int32 = 1,
            int64 = 2,
            string = 3,
            phandle = 4,
            string_list = 5,
        };

        inline fn align_to_u32(i: u64) u64 {
            return align_forward(i, @sizeOf(u32));
        }
    };
};

pub const Result = struct {
    memory_regions: [1024]Memory.Region.Descriptor,
    memory_region_count: u64,
    reserved_memory_regions: [64]Memory.Region.Descriptor,
    reserved_memory_region_count: u64,
    address: u64,
};

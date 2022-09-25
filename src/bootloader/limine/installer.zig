const std = @import("std");
const assert = std.debug.assert;
const builtin = @import("builtin");

comptime {
    std.assert(@import("builtin").cpu.arch.endian() == .Little);
}

const InstallerError = error{
    not_64_bit,
    unable_to_get_arguments,
    image_file_not_found,
    unable_to_get_file_size,
    unable_to_allocate_memory_for_file,
    unable_to_read_file_into_memory,
    secondary_GPT_header_invalid,
    invalid_partition_table,
};

const GPT = struct {
    const Header = extern struct {
        signature: u64 align(4),
        revision: u32,
        header_size: u32,
        CRC32: u32,
        _reserved0: u32,

        LBA: u64 align(4),
        alternate_LBA: u64 align(4),
        first_usable_LBA: u64 align(4),
        last_usable_LBA: u64 align(4),

        disk_GUID_0: [2]u64 align(4),

        partition_entry_LBA: u64 align(4),
        partition_entry_count: u32,
        partition_entry_size: u32,
        partition_entry_array_CRC32: u32,

        comptime {
            const expected_size = @sizeOf([8]u8) + (4 * @sizeOf(u32)) + (4 * @sizeOf(u64)) + (2 * @sizeOf(u64)) + @sizeOf(u64) + (3 * @sizeOf(u32));
            std.debug.assert(expected_size == 92);
            std.debug.assert(@sizeOf(Header) == expected_size);
        }
    };

    const Entry = extern struct {
        partition_type_guid0: u64,
        partition_type_guid1: u64,
        unique_partition_guid0: u64,
        unique_partition_guid1: u64,
        starting_LBA: u64,
        ending_LBA: u64,
        attributes: u64,
        partition_name: [36]u16,

        comptime {
            const expected_size = @sizeOf([2]u64) + (2 * @sizeOf(u64)) + (3 * @sizeOf(u64)) + (36 * @sizeOf(u16));
            std.debug.assert(expected_size == 128);
            std.debug.assert(@sizeOf(Entry) == expected_size);
        }
    };
};

var format_buffer: [8192]u8 = undefined;
fn print(comptime format: []const u8, args: anytype) void {
    const format_buffer_slice = std.fmt.bufPrint(&format_buffer, format, args) catch @panic("Unable to format stdout buffer\n");
    stdout_write(format_buffer_slice);
}

fn stdout_write(bytes: []const u8) void {
    _ = std.io.getStdOut().write(bytes) catch @panic("Unable to write to stdout\n");
}

fn print_error_and_exit(e: InstallerError) InstallerError {
    print("An error occurred: {}\n", .{e});
    return e;
}

const gpt_header_signature = @ptrCast(*align(1) const u64, "EFI PART").*;

fn div_roundup(a: u64, b: u64) u64 {
    return (((a) + ((b) - 1)) / (b));
}

fn crc32(bytes: []const u8) u32 {
    var result: u32 = std.math.maxInt(u32);
    for (bytes) |byte| {
        result = (result >> 8) ^ crc32_table[@truncate(u8, result ^ byte)];
    }

    result ^= std.math.maxInt(u32);
    return result;
}

const crc32_table = [_]u32{ 0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f, 0xe963a535, 0x9e6495a3, 0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988, 0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91, 0x1db71064, 0x6ab020f2, 0xf3b97148, 0x84be41de, 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7, 0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9, 0xfa0f3d63, 0x8d080df5, 0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172, 0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b, 0x35b5a8fa, 0x42b2986c, 0xdbbbc9d6, 0xacbcf940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59, 0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423, 0xcfba9599, 0xb8bda50f, 0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924, 0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d, 0x76dc4190, 0x01db7106, 0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433, 0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d, 0x91646c97, 0xe6635c01, 0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e, 0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457, 0x65b0d9c6, 0x12b7e950, 0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65, 0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7, 0xa4d1c46d, 0xd3d6f4fb, 0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0, 0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9, 0x5005713c, 0x270241aa, 0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f, 0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81, 0xb7bd5c3b, 0xc0ba6cad, 0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a, 0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683, 0xe3630b12, 0x94643b84, 0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1, 0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb, 0x196c3671, 0x6e6b06e7, 0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc, 0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5, 0xd6d6a3e8, 0xa1d1937e, 0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b, 0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55, 0x316e8eef, 0x4669be79, 0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236, 0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f, 0xc5ba3bbe, 0xb2bd0b28, 0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d, 0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f, 0x72076785, 0x05005713, 0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38, 0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21, 0x86d3d2d4, 0xf1d4e242, 0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777, 0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69, 0x616bffd3, 0x166ccf45, 0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2, 0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db, 0xaed16a4a, 0xd9d65adc, 0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9, 0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693, 0x54de5729, 0x23d967bf, 0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94, 0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d };

const stage2 = @embedFile("limine-hdd.bin");

pub fn install(image_path: []const u8, force_mbr: bool, partition_number: ?u32) InstallerError!void {
    if (@sizeOf(usize) != @sizeOf(u64)) return print_error_and_exit(InstallerError.not_64_bit);

    const device_array_list = blk: {
        const device_file_handle = std.fs.cwd().openFile(image_path, .{}) catch return print_error_and_exit(InstallerError.image_file_not_found); // read only
        defer device_file_handle.close();
        const device_size = device_file_handle.getEndPos() catch return print_error_and_exit(InstallerError.unable_to_get_file_size);
        var file_content = std.ArrayList(u8).initCapacity(std.heap.page_allocator, device_size) catch return print_error_and_exit(InstallerError.unable_to_allocate_memory_for_file);
        file_content.items.len = file_content.capacity;
        // @TODO -> check properly if the file has been read
        _ = device_file_handle.readAll(file_content.items) catch return print_error_and_exit(InstallerError.unable_to_read_file_into_memory);
        //print("Read byte count: {}. File content: {}\n", .{read_byte_count, file_content.items.len});
        //if (read_byte_count != file_content.items.len) return print_error_and_exit(InstallerError.unable_to_read_file_into_memory);
        break :blk file_content;
    };
    const device = device_array_list.items;
    defer device_array_list.deinit();

    // Point to the second block where the GPT header might be
    var do_gpt = false;
    var gpt_header: *GPT.Header = undefined;
    const lb_guesses = [_]u64{ 512, 4096 };
    var lb_size: u64 = 0;

    for (lb_guesses) |guess| {
        gpt_header = @ptrCast(*GPT.Header, @alignCast(@alignOf(GPT.Header), &device[guess]));
        if (gpt_header.signature == gpt_header_signature) {
            lb_size = guess;
            do_gpt = !force_mbr;
            if (force_mbr) {
                gpt_header.* = std.mem.zeroes(GPT.Header);
            }
            break;
        }
    }

    const secondary_GPT_header = @ptrCast(*GPT.Header, @alignCast(@alignOf(GPT.Header), &device[lb_size * gpt_header.alternate_LBA]));
    if (do_gpt) {
        //print("Installing to GPT. Logical block size of {}\nSecondary header at LBA 0x{x}\n", .{lb_size, gpt_header.alternate_LBA});
        if (secondary_GPT_header.signature != gpt_header_signature) {
            return print_error_and_exit(InstallerError.secondary_GPT_header_invalid);
        }

        //stdout_write("Secondary header valid\n");
    } else {
        var mbr = true;

        // Do MBR sanity checks

        {
            const hint = @ptrCast(*u8, &device[446]);
            if (hint.* != 0 and hint.* != 0x80) {
                if (!force_mbr) mbr = false else hint.* = if (hint.* & 0x80 != 0) 0x80 else 0;
            }
        }

        {
            const hint = @ptrCast(*u8, &device[462]);
            if (hint.* != 0 and hint.* != 0x80) {
                if (!force_mbr) mbr = false else hint.* = if (hint.* & 0x80 != 0) 0x80 else 0;
            }
        }

        {
            const hint = @ptrCast(*u8, &device[478]);
            if (hint.* != 0 and hint.* != 0x80) {
                if (!force_mbr) mbr = false else hint.* = if (hint.* & 0x80 != 0) 0x80 else 0;
            }
        }

        {
            const hint = @ptrCast(*u8, &device[494]);
            if (hint.* != 0 and hint.* != 0x80) {
                if (!force_mbr) mbr = false else hint.* = if (hint.* & 0x80 != 0) 0x80 else 0;
            }
        }

        {
            const hint = @ptrCast(*[8]u8, &device[4]);
            if (std.mem.eql(u8, hint, "_ECH_FS_")) {
                if (!force_mbr) mbr = false else hint.* = std.mem.zeroes([8]u8);
            }
        }

        {
            const hint = @ptrCast(*[4]u8, &device[3]);
            if (std.mem.eql(u8, hint, "NTFS")) {
                if (!force_mbr) mbr = false else hint.* = std.mem.zeroes([4]u8);
            }
        }

        {
            const hint = @ptrCast(*[5]u8, &device[54]);
            if (std.mem.eql(u8, hint[0..3], "FAT")) {
                if (!force_mbr) mbr = false else hint.* = std.mem.zeroes([5]u8);
            }
        }

        {
            const hint = @ptrCast(*[5]u8, &device[82]);
            if (std.mem.eql(u8, hint[0..3], "FAT")) {
                if (!force_mbr) mbr = false else hint.* = std.mem.zeroes([5]u8);
            }
        }

        {
            const hint = @ptrCast(*[5]u8, &device[3]);
            if (std.mem.eql(u8, hint, "FAT32")) {
                if (!force_mbr) mbr = false else hint.* = std.mem.zeroes([5]u8);
            }
        }

        {
            const hint = @ptrCast(*align(1) u16, &device[1080]);
            if (hint.* == 0xef53) {
                if (!force_mbr) mbr = false else hint.* = 0;
            }
        }

        if (!mbr) return print_error_and_exit(InstallerError.invalid_partition_table);
    }

    const stage2_size = stage2.len - 512;
    const stage2_sections = div_roundup(stage2_size, 512);
    var stage2_size_a = @intCast(u16, (stage2_sections / 2) * 512 + @as(u64, if (stage2_sections % 2 != 0) 512 else 0));
    const stage2_size_b = @intCast(u16, (stage2_sections / 2) * 512);

    var stage2_loc_a: u64 = 512;
    var stage2_loc_b = stage2_loc_a + stage2_size_a;

    if (do_gpt) {
        if (partition_number != null) {
            @panic("todo");
        } else {
            //stdout_write("GPT partition not specified. Attempting GPT embedding\n");

            const partition_entry_count = gpt_header.partition_entry_count;
            if (partition_entry_count == 0) @panic("no partitions");
            const partition_entry_base_address = @ptrToInt(device.ptr) + (gpt_header.partition_entry_LBA * lb_size);
            var partition_entry_address = partition_entry_base_address;

            var max_partition_entry_used: u64 = 0;

            var partition_entry_i: u64 = 0;
            while (partition_entry_i < partition_entry_count) : (partition_entry_i += 1) {
                const partition_entry = @intToPtr(*GPT.Entry, partition_entry_address);
                defer partition_entry_address += gpt_header.partition_entry_size;

                if (partition_entry.unique_partition_guid0 != 0 or partition_entry.unique_partition_guid1 != 0) {
                    if (partition_entry_i > max_partition_entry_used) max_partition_entry_used = partition_entry_i;
                }
            }

            stage2_loc_a = (gpt_header.partition_entry_LBA + 32) * lb_size;
            stage2_loc_a -= stage2_size_a;
            stage2_loc_a &= ~(lb_size - 1);

            stage2_loc_b = (secondary_GPT_header.partition_entry_LBA + 32) * lb_size;
            stage2_loc_b -= stage2_size_b;
            stage2_loc_b &= ~(lb_size - 1);

            const partition_entry_per_lb_count = lb_size / gpt_header.partition_entry_size;
            const new_partition_array_lba_size = stage2_loc_a / lb_size - gpt_header.partition_entry_LBA;
            const new_partition_entry_count = new_partition_array_lba_size * partition_entry_per_lb_count;

            if (new_partition_entry_count <= max_partition_entry_used) {
                @panic("todo");
            }

            //print("New maximum count of partition entries: {}\n", .{new_partition_entry_count});

            std.mem.set(u8, device[gpt_header.partition_entry_LBA * lb_size .. (gpt_header.partition_entry_LBA * lb_size) + ((max_partition_entry_used + 1) * gpt_header.partition_entry_size)], 0);
            std.mem.set(u8, device[secondary_GPT_header.partition_entry_LBA * lb_size .. (secondary_GPT_header.partition_entry_LBA * lb_size) + ((max_partition_entry_used + 1) * secondary_GPT_header.partition_entry_size)], 0);

            assert(gpt_header.partition_entry_count * @sizeOf(GPT.Entry) == gpt_header.partition_entry_count * gpt_header.partition_entry_size);
            assert(secondary_GPT_header.partition_entry_count * @sizeOf(GPT.Entry) == secondary_GPT_header.partition_entry_count * secondary_GPT_header.partition_entry_size);

            gpt_header.partition_entry_array_CRC32 = crc32(@intToPtr([*]u8, partition_entry_base_address)[0 .. new_partition_entry_count * gpt_header.partition_entry_size]);
            gpt_header.partition_entry_count = @intCast(u32, new_partition_entry_count);
            gpt_header.CRC32 = 0;
            gpt_header.CRC32 = crc32(std.mem.asBytes(gpt_header));

            secondary_GPT_header.partition_entry_array_CRC32 = gpt_header.partition_entry_array_CRC32;
            secondary_GPT_header.partition_entry_count = @intCast(u32, new_partition_entry_count);
            secondary_GPT_header.CRC32 = 0;
            secondary_GPT_header.CRC32 = crc32(std.mem.asBytes(secondary_GPT_header));
        }
    } else {
        //stdout_write("Installing to MBR\n");
    }

    // print("Stage 2 to be located at 0x{x} and 0x{x}\n", .{stage2_loc_a, stage2_loc_b});

    const original_timestamp = @ptrCast(*[6]u8, &device[218]).*;
    const original_partition_table = @ptrCast(*[70]u8, &device[440]).*;
    std.mem.copy(u8, device[0..512], stage2[0..512]);
    std.mem.copy(u8, device[512 .. 512 + stage2_size_a], stage2[512 .. 512 + stage2_size_a]);
    const size_left = stage2_size - stage2_size_a;
    std.mem.copy(u8, device[stage2_loc_b .. stage2_loc_b + size_left], stage2[512 + stage2_size_a .. 512 + stage2_size_a + size_left]);

    @ptrCast(*align(1) u16, &device[0x1a4 + 0]).* = stage2_size_a;
    @ptrCast(*align(1) u16, &device[0x1a4 + 2]).* = stage2_size_b;
    @ptrCast(*align(1) u64, &device[0x1a4 + 4]).* = stage2_loc_a;
    @ptrCast(*align(1) u64, &device[0x1a4 + 12]).* = stage2_loc_b;

    @ptrCast(*[6]u8, &device[218]).* = original_timestamp;
    @ptrCast(*[70]u8, &device[440]).* = original_partition_table;
}

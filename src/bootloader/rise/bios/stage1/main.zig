const lib = @import("lib");
const log = lib.log.scoped(.bios);
const privileged = @import("privileged");
const MemoryMap = privileged.MemoryMap;
const MemoryManager = privileged.MemoryManager;
const PhysicalAddress = privileged.PhysicalAddress;
const PhysicalHeap = privileged.PhysicalHeap;
const PhysicalMemoryRegion = privileged.PhysicalMemoryRegion;
const VirtualAddressSpace = privileged.VirtualAddressSpace;

const BIOS = privileged.BIOS;
const x86_64_GDT = privileged.arch.x86_64.GDT;

export fn loop() noreturn {
    asm volatile (
        \\cli
        \\hlt
    );

    while (true) {}
}

extern const loader_start: u8;
extern const loader_end: u8;
var bios_disk = BIOS.Disk{
    .disk = .{
        // TODO:
        .disk_size = 64 * 1024 * 1024,
        .sector_size = 0x200,
        .callbacks = .{
            .read = BIOS.Disk.read,
            .write = BIOS.Disk.write,
        },
        .type = .bios,
    },
};

pub const writer = privileged.E9Writer{ .context = {} };

pub const std_options = struct {
    pub fn logFn(comptime level: lib.log.Level, comptime scope: @TypeOf(.EnumLiteral), comptime format: []const u8, args: anytype) void {
        _ = level;
        _ = scope;
        writer.print(format, args) catch unreachable;
        writer.writeByte('\n') catch unreachable;
    }

    pub const log_level = .debug;
};

pub fn panic(message: []const u8, stack_trace: ?*lib.StackTrace, ret_addr: ?usize) noreturn {
    _ = stack_trace;
    _ = ret_addr;

    while (true) {
        asm volatile("cli");
        writer.writeAll("PANIC: ") catch unreachable;
        writer.writeAll(message) catch unreachable;
        writer.writeByte('\n') catch unreachable;
        asm volatile ("hlt");
    }
}

var files: [16]struct { path: []const u8, content: []const u8 } = undefined;
var file_count: u8 = 0;


var gdt = x86_64_GDT.Table{
    .tss_descriptor = undefined,
};

export fn entry_point() callconv(.C) noreturn {
    writer.writeAll("Hello loader\n") catch unreachable;
    BIOS.a20_enable() catch @panic("can't enable a20");
    const memory_map_entries = BIOS.e820_init() catch @panic("can't init e820");
    const memory_map_result = MemoryMap.fromBIOS(memory_map_entries);
    var memory_manager = MemoryManager.Interface(.bios).from_memory_map(memory_map_result.memory_map, memory_map_result.entry_index);
    var physical_heap = PhysicalHeap{
        .page_allocator = &memory_manager.allocator,
    };
    const allocator = &physical_heap.allocator;

    if (bios_disk.disk.sector_size != 0x200) {
       @panic("Wtf");
    }

    const gpt_cache = lib.PartitionTable.GPT.Partition.Cache.fromPartitionIndex(&bios_disk.disk, 0, allocator) catch @panic("can't load gpt cache");
    const fat_cache = lib.Filesystem.FAT32.Cache.fromGPTPartitionCache(allocator, gpt_cache) catch @panic("can't load fat cache");
    const rise_files_file = fat_cache.read_file(allocator, "/files") catch @panic("cant load json from disk");
    var file_parser = lib.FileParser.init(rise_files_file);
    while (file_parser.next() catch @panic("parser error")) |file_descriptor| {
        if (file_count == files.len) @panic("max files");
        log.debug("About to read the file: {s}", .{file_descriptor.guest});
        const file_content = fat_cache.read_file(allocator, file_descriptor.guest) catch @panic("cant read file");
        files[file_count] = .{
            .path = file_descriptor.guest,
            .content = file_content,
        };
        file_count += 1;
    }
    writer.writeAll("Bye loader\n") catch unreachable;

    const LongModeVirtualAddressSpace = privileged.ArchVirtualAddressSpace(.x86_64);
    var kernel_address_space = blk: {
        const allocation_result = physical_heap.page_allocator.allocateBytes(privileged.arch.x86_64.paging.needed_physical_memory_for_bootstrapping_kernel_address_space, lib.arch.valid_page_sizes[0]) catch @panic("Unable to get physical memory to bootstrap kernel address space");
        const kernel_address_space_physical_region = PhysicalMemoryRegion(.local){
            .address = PhysicalAddress(.local).new(allocation_result.address),
            .size = LongModeVirtualAddressSpace.needed_physical_memory_for_bootstrapping_kernel_address_space,
        };
        break :blk LongModeVirtualAddressSpace.kernel_bsp(kernel_address_space_physical_region);
    };

    for (memory_map_entries) |entry, entry_index| {
        log.debug("mapping entry {}...", .{entry_index});
        const physical_address = PhysicalAddress(.global).maybe_invalid(entry.base);
        LongModeVirtualAddressSpace.paging.bootstrap_map(&kernel_address_space, .global, physical_address, physical_address.to_identity_mapped_virtual_address(), entry.len, .{ .write = true, .execute = true }, physical_heap.page_allocator) catch @panic("mapping failed");
    }

    // Enable PAE
    {
        var cr4 = asm volatile (
                \\mov %%cr4, %[cr4]
                : [cr4] "=r" (-> u32),
                );
        cr4 |= (1 << 5);
        asm volatile(
                \\mov %[cr4], %%cr4 
                :: [cr4] "r" (cr4));
    }

    kernel_address_space.make_current();

    // Enable long mode 
    {
        var efer = privileged.arch.x86_64.registers.IA32_EFER.read();
        efer.LME = true;
        efer.write();
    }

    // Enable paging
    {
        var cr0 = asm volatile (
                \\mov %%cr0, %[cr0]
                : [cr0] "=r" (-> u32),
                );
        cr0 |= (1 << 31);
        asm volatile(
                \\mov %[cr0], %%cr0 
                :: [cr0] "r" (cr0));
    }

    writer.writeAll("Long mode activated!\n") catch unreachable;

    gdt.setup(0, false);

    writer.writeAll("GDT loaded!\n") catch unreachable;

    for (files) |file| {
        if (lib.equal(u8, file.path, "/STAGE2")) {
            var parser = lib.ELF(64).Parser.init(file.content) catch @panic("Can't parser ELF");

            const program_headers = parser.getProgramHeaders();
            for (program_headers) |*ph| {
                switch (ph.type) {
                    .load => {
                        if (ph.size_in_memory == 0) continue;

                        if (!ph.flags.readable) {
                            @panic("ELF program segment is marked as non-readable");
                        }

                        if (ph.size_in_file != ph.size_in_memory) {
                            @panic("ELF program segment file size is smaller than memory size");
                        }

                        const dst_slice = @intToPtr([*]u8, @intCast(usize, ph.physical_address))[0..@intCast(usize, ph.size_in_memory)];
                        const src_slice = @intToPtr([*]const u8, @ptrToInt(file.content.ptr) + @intCast(usize, ph.offset))[0..@intCast(usize, ph.size_in_file)];
                        if (!(dst_slice.len >= src_slice.len)) {
                            @panic("WTFFFFFFF");
                        }

                        lib.copy(u8, dst_slice, src_slice);
                    },
                        else => {
                            log.warn("Unhandled PH {s}", .{@tagName(ph.type)});
                        },
                }
            }


            comptime {
                lib.assert(@offsetOf(x86_64_GDT.Table, "code_64") == 0x08);
            }

            // TODO: figure out a way to make this not hardcoded
            asm volatile(
                    \\jmp $0x8, $0x10000
                    );
            @panic("todo: parser");
        }
    }

    @panic("loader not found");
}

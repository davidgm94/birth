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
        writer.writeAll("PANIC: ") catch unreachable;
        writer.writeAll(message) catch unreachable;
        writer.writeByte('\n') catch unreachable;
        asm volatile ("cli\nhlt");
    }
}

var files: [16]struct { path: []const u8, content: []const u8 } = undefined;
var file_count: u8 = 0;

export fn _start() callconv(.C) noreturn {
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


    const LongModeVirtualAddressSpace = privileged.ArchVirtualAddressSpace(.x86_64);
    var kernel_address_space = blk: {
        const allocation_result = physical_heap.page_allocator.allocateBytes(privileged.arch.x86_64.paging.needed_physical_memory_for_bootstrapping_kernel_address_space, lib.arch.valid_page_sizes[0]) catch @panic("Unable to get physical memory to bootstrap kernel address space");
        const kernel_address_space_physical_region = PhysicalMemoryRegion(.local){
            .address = PhysicalAddress(.local).new(allocation_result.address),
            .size = LongModeVirtualAddressSpace.needed_physical_memory_for_bootstrapping_kernel_address_space,
        };
        break :blk LongModeVirtualAddressSpace.kernel_bsp(kernel_address_space_physical_region);
    };

    _ = kernel_address_space;

    while (true) {
        writer.writeAll("loader is nicely loaded\n") catch unreachable;
        asm volatile (
            \\cli
            \\hlt
        );
    }
}

const lib = @import("lib");
const privileged = @import("privileged");
const MemoryMap = privileged.MemoryMap;
const MemoryManager = privileged.MemoryManager;
const PhysicalHeap = privileged.PhysicalHeap;

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
pub fn write_message(message: []const u8) void {
    writer.writeAll(message) catch unreachable;
}

pub fn print(comptime format: []const u8, arguments: anytype) void {
    writer.print(format, arguments) catch @panic("WTF");
}

pub fn panic(message: []const u8, stack_trace: ?*lib.StackTrace, ret_addr: ?usize) noreturn {
    _ = stack_trace;
    _ = ret_addr;


    write_message(message);
    while (true) {
    asm volatile("cli\nhlt");
        }
}

export fn _start() callconv(.C) noreturn {
    BIOS.a20_enable() catch @panic("can't enable a20");
    const memory_map_entries = BIOS.e820_init() catch @panic("can't init e820");
    const memory_map_result = MemoryMap.fromBIOS(memory_map_entries);
    _ = memory_map_result;
    // var memory_manager = MemoryManager.Interface(.bios).from_memory_map(memory_map_result.memory_map, memory_map_result.entry_index);
    // var physical_heap = PhysicalHeap{
    //     .page_allocator = &memory_manager.allocator,
    // };
    // // const allocator = &physical_heap.allocator;
    // _ = allocator;
    while (true) {
        write_message("hello loader\n");
        asm volatile(
        \\cli
        \\hlt
        );
    }

    //if (bios_disk.disk.sector_size != 0x200) {
    //    @panic("Wtf");
    //}


    //const gpt_cache = lib.PartitionTable.GPT.Partition.Cache.fromPartitionIndex(&bios_disk.disk, 0, allocator) catch @panic("can't load gpt cache");
    //const fat_cache = lib.Filesystem.FAT32.Cache.fromGPTPartitionCache(allocator, gpt_cache) catch @panic("can't load fat cache");
    //_ = fat_cache;

    //write_message("End of bootloader\n");
    //loop();
}

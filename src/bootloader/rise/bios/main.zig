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

var real_mode_ds: u16 = 0;

export fn _start() noreturn {
    logger.debug("Hello loader!", .{});
    BIOS.a20_enable() catch @panic("can't enable a20");
    const memory_map_entries = BIOS.e820_init() catch @panic("can't init e820");
    const memory_map_result = MemoryMap.fromBIOS(memory_map_entries);
    var memory_manager = MemoryManager.Interface(.bios).from_memory_map(memory_map_result.memory_map, memory_map_result.entry_index);
    var physical_heap = PhysicalHeap{
        .page_allocator = &memory_manager.allocator,
    };

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

    const disk = &bios_disk.disk;
    const allocator = &physical_heap.allocator;

    const partition_cache = lib.PartitionTable.GPT.Partition.Cache.fromPartitionIndex(disk, 0, allocator) catch @panic("can't load partition cache");
    _ = partition_cache;

    logger.debug("End of bootloader", .{});
    loop();
}

pub const std_options = struct {
    pub fn logFn(comptime level: lib.log.Level, comptime scope: @TypeOf(.EnumLiteral), comptime format: []const u8, args: anytype) void {
        const scope_prefix = if (scope == .default) ": " else "(" ++ @tagName(scope) ++ "): ";
        const prefix = "[" ++ @tagName(level) ++ "] " ++ scope_prefix;
        writer.print(prefix ++ format ++ "\n", args) catch unreachable;
    }
    pub const log_level = .debug;
};

pub const logger = lib.log.scoped(.Loader);
pub const log_level = lib.log.Level.debug;
pub const writer = privileged.E9Writer{ .context = {} };

pub fn panic(message: []const u8, stack_trace: ?*lib.StackTrace, ret_addr: ?usize) noreturn {
    _ = stack_trace;
    _ = ret_addr;

    lib.log.scoped(.PANIC).err("{s}", .{message});
    asm volatile (
        \\cli
        \\hlt
    );
    while (true) {}
}

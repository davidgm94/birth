const lib = @import("lib");
const Allocator = lib.Allocator;
const assert = lib.assert;
const log = lib.log;

const bootloader = @import("bootloader");

const privileged = @import("privileged");
const CPUPageTables = privileged.arch.CPUPageTables;
const Mapping = privileged.Mapping;
const PageAllocatorInterface = privileged.PageAllocator;
const PhysicalAddress = privileged.PhysicalAddress;
const PhysicalAddressSpace = privileged.PhysicalAddressSpace;
const PhysicalMemoryRegion = privileged.PhysicalMemoryRegion;
const stopCPU = privileged.arch.stopCPU;
const VirtualAddress = privileged.VirtualAddress;
const VirtualMemoryRegion = privileged.VirtualMemoryRegion;

const rise = @import("rise");

pub const test_runner = @import("cpu/test_runner.zig");
pub const arch = @import("cpu/arch.zig");
pub const capabilities = @import("cpu/capabilities.zig");

pub export var stack: [0x8000]u8 align(0x1000) = undefined;
pub export var heap_allocator = Heap{};
pub export var page_allocator = PageAllocator{
    .head = null,
    .list_allocator = .{
        .u = .{
            .primitive = .{
                .backing_4k_page = undefined,
                .allocated = 0,
            },
        },
        .primitive = true,
    },
};

pub export var user_scheduler: *UserScheduler = undefined;
pub export var driver: *align(lib.arch.valid_page_sizes[0]) Driver = undefined;
pub export var page_tables: CPUPageTables = undefined;
pub var file: []align(lib.default_sector_size) const u8 = undefined;
pub export var core_id: u32 = 0;
pub export var bsp = false;
var panic_lock = lib.Spinlock.released;

pub const writer = arch.writer;

/// This data structure holds the information needed to run a core
pub const Driver = extern struct {
    init_root: capabilities.Root,
    valid: bool = false,
    padding: [lib.arch.valid_page_sizes[0] - @sizeOf(bool) - @sizeOf(capabilities.Root)]u8,

    comptime {
        // @compileLog(@sizeOf(Driver));

        assert(lib.isAligned(@sizeOf(Driver), lib.arch.valid_page_sizes[0]));
    }
};

/// This data structure holds the information needed to run a program in a core (cpu side)
pub const UserScheduler = extern struct {
    common: *rise.UserScheduler,
    capability_root_node: capabilities.Root,
    padding: [padding_len]u8 = .{0} ** padding_len,
    const padding_len = lib.arch.valid_page_sizes[0] - @sizeOf(capabilities.Root) - @sizeOf(*rise.UserScheduler);

    comptime {
        assert(@sizeOf(UserScheduler) == lib.arch.valid_page_sizes[0]);
    }
};

pub const Heap = extern struct {
    region: VirtualMemoryRegion = .{
        .address = .null,
        .size = 0,
    },

    var allocated: u64 = 0;

    pub inline fn fromPageAllocator(pa: *PageAllocator) !Heap {
        const physical_allocation = try pa.allocate(lib.arch.valid_page_sizes[1], lib.arch.valid_page_sizes[1]);
        const virtual_allocation = physical_allocation.toHigherHalfVirtualAddress();
        return Heap{
            .region = virtual_allocation,
        };
    }

    pub inline fn allocate(heap: *Heap, comptime T: type, count: usize) Allocator.Allocate.Error!*T {
        const region = try heap.allocateBytes(@sizeOf(T) * count, @alignOf(T));
        return region.access(T);
    }

    pub inline fn create(heap: *Heap, comptime T: type) Allocator.Allocate.Error!*T {
        const region = try heap.allocateBytes(@sizeOf(T), @alignOf(T));
        return region.address.access(*T);
    }

    pub noinline fn allocateBytes(heap: *Heap, size: u64, alignment: u64) Allocator.Allocate.Error!VirtualMemoryRegion {
        const target_address = lib.alignForward(heap.region.address.value(), alignment);
        const alignment_diff = target_address - heap.region.address.value();
        const aligned_size = size + alignment_diff;

        allocated += size;

        if (heap.region.size >= aligned_size) {
            const result_address = VirtualAddress.new(target_address);
            heap.region.size -= aligned_size;
            heap.region.address = heap.region.address.offset(aligned_size);

            return .{
                .address = result_address,
                .size = size,
            };
        } else {
            assert(alignment < lib.arch.valid_page_sizes[0]);
            const region_allocation_size = if (lib.arch.valid_page_sizes[0] >= size) lib.arch.valid_page_sizes[0] else lib.alignForward(size, lib.arch.valid_page_sizes[0]);
            const region_allocation = try page_allocator.allocate(region_allocation_size, lib.arch.valid_page_sizes[0]);
            const virtual_region = region_allocation.toHigherHalfVirtualAddress();
            heap.region = virtual_region;

            const result_address = heap.region.address;

            heap.region.size -= size;
            heap.region.address = heap.region.address.offset(size);

            return .{
                .address = result_address,
                .size = size,
            };
        }
    }

    pub inline fn toZig(heap: *Heap) lib.ZigAllocator {
        return .{
            .ptr = heap,
            .vtable = &zig_vtable,
        };
    }

    fn zigAllocate(ctx: *anyopaque, n: usize, log2_ptr_align: u8, ra: usize) ?[*]u8 {
        _ = log2_ptr_align;
        _ = ra;
        const heap = @ptrCast(*Heap, @alignCast(@alignOf(Heap), ctx));
        const virtual_memory_region = heap.allocateBytes(n, 8) catch return null;
        return virtual_memory_region.address.access(?[*]u8);
    }

    fn zigResize(
        ctx: *anyopaque,
        buf: []u8,
        log2_buf_align: u8,
        new_size: usize,
        return_address: usize,
    ) bool {
        _ = return_address;
        _ = new_size;
        _ = log2_buf_align;
        _ = buf;
        _ = ctx;

        return false;
    }

    fn zigFree(
        ctx: *anyopaque,
        buf: []u8,
        log2_buf_align: u8,
        return_address: usize,
    ) void {
        _ = return_address;
        _ = log2_buf_align;
        _ = buf;
        _ = ctx;
    }

    pub const zig_vtable = lib.ZigAllocator.VTable{
        .alloc = zigAllocate,
        .free = zigFree,
        .resize = zigResize,
    };

    pub const Entry = PageAllocator.Entry;
};

const print_stack_trace = false;
var panic_count: usize = 0;

inline fn panicPrologue(comptime format: []const u8, arguments: anytype) !void {
    panic_count += 1;
    privileged.arch.disableInterrupts();
    if (panic_count == 1) panic_lock.acquire();

    try writer.writeAll("[CPU DRIVER] [PANIC] ");
    try writer.print(format, arguments);
    try writer.writeByte('\n');
}

inline fn panicEpilogue() noreturn {
    if (panic_count == 1) panic_lock.release();

    if (lib.is_test) {
        privileged.exitFromQEMU(.failure);
    } else {
        privileged.arch.stopCPU();
    }
}

inline fn printStackTrace(maybe_stack_trace: ?*lib.StackTrace) !void {
    if (maybe_stack_trace) |stack_trace| {
        var debug_info = try getDebugInformation();
        try writer.writeAll("Stack trace:\n");
        var frame_index: usize = 0;
        var frames_left: usize = @min(stack_trace.index, stack_trace.instruction_addresses.len);

        while (frames_left != 0) : ({
            frames_left -= 1;
            frame_index = (frame_index + 1) % stack_trace.instruction_addresses.len;
        }) {
            const return_address = stack_trace.instruction_addresses[frame_index];
            try writer.print("[{}] ", .{frame_index});
            try printSourceAtAddress(&debug_info, return_address);
        }
    } else {
        try writer.writeAll("Stack trace not available\n");
    }
}

inline fn printStackTraceFromStackIterator(return_address: usize, frame_address: usize) !void {
    var debug_info = try getDebugInformation();
    var stack_iterator = lib.StackIterator.init(return_address, frame_address);
    var frame_index: usize = 0;
    try writer.writeAll("Stack trace:\n");

    try printSourceAtAddress(&debug_info, return_address);
    while (stack_iterator.next()) |address| : (frame_index += 1) {
        try writer.print("[{}] ", .{frame_index});
        try printSourceAtAddress(&debug_info, address);
    }
}

fn printSourceAtAddress(debug_info: *lib.ModuleDebugInfo, address: usize) !void {
    if (debug_info.findCompileUnit(address)) |compile_unit| {
        const symbol = .{
            .symbol_name = debug_info.getSymbolName(address) orelse "???",
            .compile_unit_name = compile_unit.die.getAttrString(debug_info, lib.dwarf.AT.name, debug_info.debug_str, compile_unit.*) catch "???",
            .line_info = debug_info.getLineNumberInfo(heap_allocator.toZig(), compile_unit.*, address) catch null,
        };
        try writer.print("0x{x}: {s}!{s} {s}:{}:{}\n", .{ address, symbol.symbol_name, symbol.compile_unit_name, symbol.line_info.?.file_name, symbol.line_info.?.line, symbol.line_info.?.column });
    } else |err| {
        return err;
    }
}

pub fn panicWithStackTrace(stack_trace: ?*lib.StackTrace, comptime format: []const u8, arguments: anytype) noreturn {
    panicPrologue(format, arguments) catch {};
    if (print_stack_trace) printStackTrace(stack_trace) catch {};
    panicEpilogue();
}

pub fn panicFromInstructionPointerAndFramePointer(return_address: usize, frame_address: usize, comptime format: []const u8, arguments: anytype) noreturn {
    panicPrologue(format, arguments) catch {};
    if (print_stack_trace) printStackTraceFromStackIterator(return_address, frame_address) catch {};
    panicEpilogue();
}

pub fn panic(comptime format: []const u8, arguments: anytype) noreturn {
    @call(.always_inline, panicFromInstructionPointerAndFramePointer, .{ @returnAddress(), @frameAddress(), format, arguments });
}

pub const UserVirtualAddressSpace = extern struct {
    generic: VirtualAddressSpace,
};

pub const VirtualAddressSpace = extern struct {
    arch: paging.Specific,
    first_page_tables: ?*PageEntry = null,
    last_page_tables: ?*PageEntry = null,
    page_table_count: usize = 0,
    heap: Heap = .{},

    pub const PageEntry = extern struct {
        address: PhysicalAddress,
        next: ?*PageEntry,
        options: packed struct(u8) {
            level: paging.Level,
            user: bool,
            reserved: u5 = 0,
        },
    };

    pub const paging = privileged.arch.current.paging;

    // pub fn new() !*VirtualAddressSpace {
    //     const virtual_address_space = try heap_allocator.create(VirtualAddressSpace);
    //
    //     virtual_address_space.* = .{
    //         .arch = undefined,
    //     };
    //
    //     virtual_address_space.arch = try paging.Specific.new(virtual_address_space.getPageAllocatorInterface(), page_tables);
    //
    //     return virtual_address_space;
    // }

    fn callbackHeapAllocate(allocator: *Allocator, size: u64, alignment: u64) Allocator.Allocate.Error!Allocator.Allocate.Result {
        _ = alignment;
        _ = size;
        _ = allocator;
        // if (lib.cpu.arch != .x86) {
        //     const virtual_address_space = @fieldParentPtr(VirtualAddressSpace, "heap", @fieldParentPtr(Heap, "allocator", allocator));
        //     _ = virtual_address_space;
        // }

        return Allocator.Allocate.Error.OutOfMemory;
    }

    pub inline fn makeCurrent(vas: *const VirtualAddressSpace) void {
        vas.arch.makeCurrent();
    }

    pub fn allocateAndMap(virtual_address_space: *VirtualAddressSpace, size: u64, alignment: u64, general_flags: Mapping.Flags) !VirtualMemoryRegion {
        const physical_region = try page_allocator.allocate(size, alignment);
        const virtual_region = switch (general_flags.user) {
            false => physical_region.toHigherHalfVirtualAddress(),
            true => physical_region.toIdentityMappedVirtualAddress(),
        };
        try virtual_address_space.map(physical_region.address, virtual_region.address, size, general_flags);
        return virtual_region;
    }

    pub fn allocateAndMapToAddress(virtual_address_space: *VirtualAddressSpace, virtual_address: VirtualAddress, size: u64, alignment: u64, general_flags: Mapping.Flags) !PhysicalMemoryRegion {
        const physical_region = try page_allocator.allocate(size, alignment);
        try virtual_address_space.map(physical_region.address, virtual_address, size, general_flags);
        return physical_region;
    }

    pub fn map(virtual_address_space: *VirtualAddressSpace, asked_physical_address: PhysicalAddress, asked_virtual_address: VirtualAddress, size: u64, general_flags: Mapping.Flags) !void {
        if (size == 0) {
            return paging.Error.invalid_size;
        }

        if (!lib.isAlignedGeneric(u64, asked_physical_address.value(), lib.arch.valid_page_sizes[0])) {
            return paging.Error.unaligned_physical;
        }

        if (!lib.isAlignedGeneric(u64, asked_virtual_address.value(), lib.arch.valid_page_sizes[0])) {
            return paging.Error.unaligned_virtual;
        }

        if (!lib.isAlignedGeneric(u64, size, lib.arch.valid_page_sizes[0])) {
            return paging.Error.unaligned_size;
        }

        if (asked_physical_address.value() >= lib.config.cpu_driver_higher_half_address) {
            return paging.Error.invalid_physical;
        }

        try arch.map(virtual_address_space, asked_physical_address, asked_virtual_address, size, general_flags);
    }

    pub inline fn mapDevice(virtual_address_space: *VirtualAddressSpace, asked_physical_address: PhysicalAddress, size: u64) !VirtualAddress {
        try virtual_address_space.map(asked_physical_address, asked_physical_address.toHigherHalfVirtualAddress(), size, .{
            .write = true,
            .cache_disable = true,
            .global = false,
        });

        return asked_physical_address.toHigherHalfVirtualAddress();
    }

    fn allocatePages(virtual_address_space: *VirtualAddressSpace, options: PageAllocatorInterface.AllocatePageTablesOptions) Allocator.Allocate.Error!PhysicalMemoryRegion {
        const alignment: u64 = switch (lib.cpu.arch) {
            .x86_64 => switch (options.count) {
                2 => 2 * paging.page_table_alignment,
                0x200 => 0x200 * paging.page_table_alignment,
                else => paging.page_table_alignment,
            },
            else => @compileError("architecture not supported"),
        };
        const result = try page_allocator.allocate(options.count * paging.page_table_size, alignment);
        const page_entry = try virtual_address_space.heap.create(PageEntry);
        page_entry.* = .{
            .address = result.address,
            .next = null,
            .options = .{
                .level = options.level,
                .user = options.user,
            },
        };

        if (virtual_address_space.last_page_tables) |last| {
            assert(virtual_address_space.page_table_count > 0);
            last.next = page_entry;
        } else {
            assert(virtual_address_space.page_table_count == 0);
            assert(virtual_address_space.first_page_tables == null);
            virtual_address_space.first_page_tables = page_entry;
        }

        virtual_address_space.last_page_tables = page_entry;

        virtual_address_space.page_table_count += options.count;

        return result;
    }

    fn callbackAllocatePages(context: ?*anyopaque, size: u64, alignment: u64, options: PageAllocatorInterface.AllocateOptions) Allocator.Allocate.Error!PhysicalMemoryRegion {
        if (size != paging.page_table_size) return error.OutOfMemory;
        if (alignment != paging.page_table_alignment) return error.OutOfMemory;
        if (!options.level_valid) return error.OutOfMemory;

        const virtual_address_space = @ptrCast(*VirtualAddressSpace, @alignCast(@alignOf(VirtualAddressSpace), context));
        return try virtual_address_space.allocatePages(.{
            .count = options.count,
            .level = options.level,
            .user = options.user,
        });
    }

    pub fn mapPageTables(virtual_address_space: *VirtualAddressSpace) !void {
        var it = virtual_address_space.first_page_tables;
        while (it != virtual_address_space.last_page_tables) {
            var last: *PageEntry = undefined;
            while (it) |page_table_entry| : (it = page_table_entry.next) {
                try virtual_address_space.map(page_table_entry.address, page_table_entry.address.toHigherHalfVirtualAddress(), paging.page_table_size, .{
                    .user = page_table_entry.options.user,
                    .write = true,
                });
                last = page_table_entry;
            }

            if (it == null) it = last;
        }
    }

    pub fn getPageAllocatorInterface(virtual_address_space: *VirtualAddressSpace) PageAllocatorInterface {
        return .{
            .allocate = VirtualAddressSpace.callbackAllocatePages,
            .context = virtual_address_space,
            .context_type = .cpu,
        };
    }
};

pub const PageAllocator = extern struct {
    head: ?*Entry,
    list_allocator: ListAllocator,
    total_allocated_size: u32 = 0,

    fn getPageAllocatorInterface(pa: *PageAllocator) PageAllocatorInterface {
        return .{
            .allocate = callbackAllocate,
            .context = pa,
            .context_type = .cpu,
        };
    }

    fn callbackAllocate(context: ?*anyopaque, size: u64, alignment: u64, options: PageAllocatorInterface.AllocateOptions) Allocator.Allocate.Error!PhysicalMemoryRegion {
        _ = options;
        const pa = @ptrCast(?*PageAllocator, @alignCast(@alignOf(PageAllocator), context)) orelse return Allocator.Allocate.Error.OutOfMemory;
        const result = try pa.allocate(size, alignment);
        return result;
    }

    pub fn allocate(pa: *PageAllocator, size: u64, alignment: u64) Allocator.Allocate.Error!PhysicalMemoryRegion {
        if (pa.head == null) {
            @panic("head null");
        }

        const allocation = blk: {
            var ptr = pa.head;
            while (ptr) |entry| : (ptr = entry.next) {
                if (lib.isAligned(entry.region.address.value(), alignment) and entry.region.size > size) {
                    const result = PhysicalMemoryRegion{
                        .address = entry.region.address,
                        .size = size,
                    };
                    entry.region.address = entry.region.address.offset(size);
                    entry.region.size -= size;

                    pa.total_allocated_size += @intCast(u32, size);
                    // log.debug("Allocated 0x{x}", .{size});

                    break :blk result;
                }
            }

            ptr = pa.head;

            while (ptr) |entry| : (ptr = entry.next) {
                const aligned_address = lib.alignForward(entry.region.address.value(), alignment);
                const top = entry.region.top().value();
                if (aligned_address < top and top - aligned_address > size) {
                    // log.debug("Found region which we should be splitting: (0x{x}, 0x{x})", .{ entry.region.address.value(), entry.region.size });
                    // log.debug("User asked for 0x{x} bytes with alignment 0x{x}", .{ size, alignment });
                    // Split the addresses to obtain the desired result
                    const first_region_size = aligned_address - entry.region.address.value();
                    const first_region_address = entry.region.address;
                    const first_region_next = entry.next;

                    const second_region_address = aligned_address + size;
                    const second_region_size = top - aligned_address + size;

                    const result = PhysicalMemoryRegion{
                        .address = PhysicalAddress.new(aligned_address),
                        .size = size,
                    };

                    // log.debug("\nFirst region: (Address: 0x{x}. Size: 0x{x}).\nRegion in the middle (allocated): (Address: 0x{x}. Size: 0x{x}).\nSecond region: (Address: 0x{x}. Size: 0x{x})", .{ first_region_address, first_region_size, result.address.value(), result.size, second_region_address, second_region_size });

                    const new_entry = pa.list_allocator.get();
                    entry.* = .{
                        .region = .{
                            .address = first_region_address,
                            .size = first_region_size,
                        },
                        .next = new_entry,
                    };

                    new_entry.* = .{
                        .region = .{
                            .address = PhysicalAddress.new(second_region_address),
                            .size = second_region_size,
                        },
                        .next = first_region_next,
                    };
                    // log.debug("First entry: (Address: 0x{x}. Size: 0x{x})", .{ entry.region.address.value(), entry.region.size });
                    // log.debug("Second entry: (Address: 0x{x}. Size: 0x{x})", .{ new_entry.region.address.value(), new_entry.region.size });

                    // pa.total_allocated_size += @intCast(u32, size);
                    // log.debug("Allocated 0x{x}", .{size});

                    break :blk result;
                }
            }

            log.err("Allocate error. Size: 0x{x}. Alignment: 0x{x}. Total allocated size: 0x{x}", .{ size, alignment, pa.total_allocated_size });
            return Allocator.Allocate.Error.OutOfMemory;
        };

        //log.debug("Physical allocation: 0x{x}, 0x{x}", .{ allocation.address.value(), allocation.size });

        @memset(allocation.toHigherHalfVirtualAddress().access(u8), 0);

        return allocation;
    }

    pub inline fn fromBSP(bootloader_information: *bootloader.Information) InitializationError!PageAllocator {
        const memory_map_entries = bootloader_information.getMemoryMapEntries();
        const page_counters = bootloader_information.getPageCounters();

        var total_size: usize = 0;
        const page_shifter = lib.arch.page_shifter(lib.arch.valid_page_sizes[0]);

        for (memory_map_entries, page_counters) |entry, page_counter| {
            if (entry.type != .usable or !lib.isAligned(entry.region.size, lib.arch.valid_page_sizes[0]) or entry.region.address.value() < lib.mb) {
                continue;
            }

            total_size += entry.region.size - (page_counter << page_shifter);
        }

        const cpu_count = bootloader_information.smp.cpu_count;
        const total_memory_to_take = total_size / cpu_count;

        // Look for a 4K page to host the memory map
        const backing_4k_page = for (memory_map_entries, page_counters) |entry, *page_counter| {
            const occupied_size = page_counter.* << page_shifter;
            const entry_size_left = entry.region.size - occupied_size;
            if (entry_size_left != 0) {
                if (entry.type != .usable or !lib.isAligned(entry.region.size, lib.arch.valid_page_sizes[0]) or entry.region.address.value() < lib.mb) continue;

                assert(lib.isAligned(entry_size_left, lib.arch.valid_page_sizes[0]));
                page_counter.* += 1;
                break entry.region.address.offset(occupied_size);
            }
        } else return InitializationError.bootstrap_region_not_found;

        var memory_taken: usize = 0;
        var backing_4k_page_memory_allocated: usize = 0;

        var last_entry: ?*Entry = null;
        var first_entry: ?*Entry = null;

        for (memory_map_entries, page_counters) |entry, *page_counter| {
            if (entry.type != .usable or !lib.isAligned(entry.region.size, lib.arch.valid_page_sizes[0]) or entry.region.address.value() < lib.mb) continue;

            const occupied_size = page_counter.* << page_shifter;

            if (occupied_size < entry.region.size) {
                var entry_size_left = entry.region.size - occupied_size;

                var memory_taken_from_region: usize = 0;
                while (memory_taken + memory_taken_from_region < total_memory_to_take) {
                    if (entry_size_left == 0) break;

                    const size_to_take = @min(2 * lib.mb, entry_size_left);
                    //log.debug("Size to take: 0x{x}", .{size_to_take});
                    entry_size_left -= size_to_take;
                    memory_taken_from_region += size_to_take;
                }

                memory_taken += memory_taken_from_region;

                page_counter.* += @intCast(u32, memory_taken_from_region >> page_shifter);
                const region_descriptor = .{
                    .address = entry.region.offset(occupied_size).address,
                    .size = memory_taken_from_region,
                };

                if (backing_4k_page_memory_allocated >= lib.arch.valid_page_sizes[0]) return InitializationError.memory_exceeded;
                const entry_address = backing_4k_page.offset(backing_4k_page_memory_allocated);
                const new_entry = entry_address.toHigherHalfVirtualAddress().access(*Entry);
                backing_4k_page_memory_allocated += @sizeOf(Entry);

                new_entry.* = .{
                    .region = .{
                        .address = region_descriptor.address,
                        .size = region_descriptor.size,
                    },
                    .next = null,
                };

                if (last_entry) |e| {
                    e.next = new_entry;
                } else {
                    first_entry = new_entry;
                }

                last_entry = new_entry;

                if (memory_taken >= total_memory_to_take) break;
            }
        }

        const result = .{
            .head = first_entry,
            .list_allocator = .{
                .u = .{
                    .primitive = .{
                        .backing_4k_page = backing_4k_page,
                        .allocated = backing_4k_page_memory_allocated,
                    },
                },
                .primitive = true,
            },
        };

        return result;
    }

    const ListAllocator = extern struct {
        u: extern union {
            primitive: extern struct {
                backing_4k_page: PhysicalAddress,
                allocated: u64,
            },
            normal: extern struct {
                foo: u64,
            },
        },
        primitive: bool,

        pub fn get(list_allocator: *ListAllocator) *Entry {
            switch (list_allocator.primitive) {
                true => {
                    if (list_allocator.u.primitive.allocated < 0x1000) {
                        const result = list_allocator.u.primitive.backing_4k_page.offset(list_allocator.u.primitive.allocated).toHigherHalfVirtualAddress().access(*Entry);
                        list_allocator.u.primitive.backing_4k_page = list_allocator.u.primitive.backing_4k_page.offset(@sizeOf(Entry));
                        return result;
                    } else {
                        @panic("reached limit");
                    }
                },
                false => {
                    @panic("not primitive allocator not implemented");
                },
            }
        }
    };

    pub const Entry = extern struct {
        region: PhysicalMemoryRegion,
        next: ?*Entry,
    };

    const InitializationError = error{
        bootstrap_region_not_found,
        memory_exceeded,
    };
};

fn getDebugInformation() !lib.ModuleDebugInfo {
    const debug_info = lib.getDebugInformation(heap_allocator.toZig(), file) catch |err| {
        try writer.print("Failed to get debug information: {}", .{err});
        return err;
    };

    return debug_info;
}

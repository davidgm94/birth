const lib = @import("lib");
const Allocator = lib.Allocator;
const assert = lib.assert;
const log = lib.log;

const bootloader = @import("bootloader");

const privileged = @import("privileged");
const CPUPageTables = privileged.arch.CPUPageTables;
const Mapping = privileged.Mapping;
const PageAllocatorInterface = privileged.PageAllocator;
const PhysicalAddress = lib.PhysicalAddress;
const PhysicalAddressSpace = lib.PhysicalAddressSpace;
const PhysicalMemoryRegion = lib.PhysicalMemoryRegion;
const stopCPU = privileged.arch.stopCPU;
const VirtualAddress = privileged.VirtualAddress;
const VirtualMemoryRegion = privileged.VirtualMemoryRegion;

const rise = @import("rise");

pub const test_runner = @import("cpu/test_runner.zig");
pub const arch = @import("cpu/arch.zig");
pub const capabilities = @import("cpu/capabilities.zig");

pub export var stack: [0x8000]u8 align(0x1000) = undefined;
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

pub var bundle: []const u8 = &.{};
pub var bundle_files: []const u8 = &.{};

pub export var user_scheduler: *UserScheduler = undefined;
pub export var driver: *align(lib.arch.valid_page_sizes[0]) Driver = undefined;
pub export var page_tables: CPUPageTables = undefined;
pub var file: []align(lib.default_sector_size) const u8 = undefined;
pub export var core_id: u32 = 0;
pub export var bsp = false;
var panic_lock = lib.Spinlock.released;

/// This data structure holds the information needed to run a core
pub const Driver = extern struct {
    init_root_capability: capabilities.RootDescriptor,
    valid: bool,
    padding: [padding_byte_count]u8 = .{0} ** padding_byte_count,
    const padding_byte_count = lib.arch.valid_page_sizes[0] - @sizeOf(bool) - @sizeOf(capabilities.RootDescriptor);

    pub inline fn getRootCapability(drv: *Driver) *capabilities.Root {
        return drv.init_root_capability.value;
    }

    comptime {
        // @compileLog(@sizeOf(Driver));
        assert(lib.isAligned(@sizeOf(Driver), lib.arch.valid_page_sizes[0]));
    }
};

/// This data structure holds the information needed to run a program in a core (cpu side)
pub const UserScheduler = extern struct {
    capability_root_node: capabilities.Root,
    common: *rise.UserScheduler,
    padding: [padding_byte_count]u8 = .{0} ** padding_byte_count,

    const total_size = @sizeOf(capabilities.Root) + @sizeOf(*rise.UserScheduler);
    const aligned_size = lib.alignForward(usize, total_size, lib.arch.valid_page_sizes[0]);
    const padding_byte_count = aligned_size - total_size;

    comptime {
        if (padding_byte_count == 0 and @hasField(UserScheduler, "padding")) {
            @compileError("remove padding because it is not necessary");
        }
    }
};

const print_stack_trace = false;
var panic_count: usize = 0;

inline fn panicPrologue(comptime format: []const u8, arguments: anytype) !void {
    panic_count += 1;
    privileged.arch.disableInterrupts();
    if (panic_count == 1) panic_lock.acquire();

    try writer.writeAll(lib.Color.get(.bold));
    try writer.writeAll(lib.Color.get(.red));
    try writer.writeAll("[CPU DRIVER] [PANIC] ");
    try writer.writeAll(lib.Color.get(.reset));
    try writer.print(format, arguments);
    try writer.writeByte('\n');
}

inline fn panicEpilogue() noreturn {
    if (panic_count == 1) panic_lock.release();

    shutdown(.failure);
}

// inline fn printStackTrace(maybe_stack_trace: ?*lib.StackTrace) !void {
//     if (maybe_stack_trace) |stack_trace| {
//         var debug_info = try getDebugInformation();
//         try writer.writeAll("Stack trace:\n");
//         var frame_index: usize = 0;
//         var frames_left: usize = @min(stack_trace.index, stack_trace.instruction_addresses.len);
//
//         while (frames_left != 0) : ({
//             frames_left -= 1;
//             frame_index = (frame_index + 1) % stack_trace.instruction_addresses.len;
//         }) {
//             const return_address = stack_trace.instruction_addresses[frame_index];
//             try writer.print("[{}] ", .{frame_index});
//             try printSourceAtAddress(&debug_info, return_address);
//         }
//     } else {
//         try writer.writeAll("Stack trace not available\n");
//     }
// }

// inline fn printStackTraceFromStackIterator(return_address: usize, frame_address: usize) !void {
//     var debug_info = try getDebugInformation();
//     var stack_iterator = lib.StackIterator.init(return_address, frame_address);
//     var frame_index: usize = 0;
//     try writer.writeAll("Stack trace:\n");
//
//     try printSourceAtAddress(&debug_info, return_address);
//     while (stack_iterator.next()) |address| : (frame_index += 1) {
//         try writer.print("[{}] ", .{frame_index});
//         try printSourceAtAddress(&debug_info, address);
//     }
// }

// fn printSourceAtAddress(debug_info: *lib.ModuleDebugInfo, address: usize) !void {
//     if (debug_info.findCompileUnit(address)) |compile_unit| {
//         const symbol = .{
//             .symbol_name = debug_info.getSymbolName(address) orelse "???",
//             .compile_unit_name = compile_unit.die.getAttrString(debug_info, lib.dwarf.AT.name, debug_info.debug_str, compile_unit.*) catch "???",
//             .line_info = debug_info.getLineNumberInfo(heap_allocator.toZig(), compile_unit.*, address) catch null,
//         };
//         try writer.print("0x{x}: {s}!{s} {s}:{}:{}\n", .{ address, symbol.symbol_name, symbol.compile_unit_name, symbol.line_info.?.file_name, symbol.line_info.?.line, symbol.line_info.?.column });
//     } else |err| {
//         return err;
//     }
// }

pub fn panicWithStackTrace(stack_trace: ?*lib.StackTrace, comptime format: []const u8, arguments: anytype) noreturn {
    _ = stack_trace;
    panicPrologue(format, arguments) catch {};
    // if (print_stack_trace) printStackTrace(stack_trace) catch {};
    panicEpilogue();
}

pub fn panicFromInstructionPointerAndFramePointer(return_address: usize, frame_address: usize, comptime format: []const u8, arguments: anytype) noreturn {
    _ = frame_address;
    _ = return_address;
    panicPrologue(format, arguments) catch {};
    //if (print_stack_trace) printStackTraceFromStackIterator(return_address, frame_address) catch {};
    panicEpilogue();
}

pub fn panic(comptime format: []const u8, arguments: anytype) noreturn {
    @call(.always_inline, panicFromInstructionPointerAndFramePointer, .{ @returnAddress(), @frameAddress(), format, arguments });
}

pub var syscall_count: usize = 0;

pub inline fn shutdown(exit_code: lib.QEMU.ExitCode) noreturn {
    log.debug("Printing stats...", .{});
    log.debug("Syscall count: {}", .{syscall_count});

    privileged.shutdown(exit_code);
}

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
        const pa = @as(?*PageAllocator, @ptrCast(@alignCast(context))) orelse return Allocator.Allocate.Error.OutOfMemory;
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

                    pa.total_allocated_size += @as(u32, @intCast(size));
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
                const entry_size_left = entry.region.size - occupied_size;

                var memory_taken_from_region: usize = 0;
                while (memory_taken + memory_taken_from_region < total_memory_to_take) {
                    if (memory_taken_from_region == entry_size_left) break;

                    const size_to_take = @min(2 * lib.mb, entry_size_left);
                    memory_taken_from_region += size_to_take;
                }

                memory_taken += memory_taken_from_region;

                page_counter.* += @as(u32, @intCast(memory_taken_from_region >> page_shifter));
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

// fn getDebugInformation() !lib.ModuleDebugInfo {
//     const debug_info = lib.getDebugInformation(heap_allocator.toZig(), file) catch |err| {
//         try writer.print("Failed to get debug information: {}", .{err});
//         return err;
//     };
//
//     return debug_info;
// }

pub const writer = privileged.E9Writer{ .context = {} };

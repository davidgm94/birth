// This package provides of privileged data structures and routines to both kernel and bootloaders, for now

const lib = @import("lib");
const assert = lib.assert;
const log = lib.log;
const maxInt = lib.maxInt;
const Allocator = lib.Allocator;

pub const arch = @import("privileged/arch.zig");
pub const Capabilities = @import("privileged/capabilities.zig");
pub const ELF = @import("privileged/elf.zig");
pub const Executable = @import("privileged/executable.zig");
pub const MappingDatabase = @import("privileged/mapping_database.zig");
pub const scheduler_type = SchedulerType.round_robin;
pub const Scheduler = switch (scheduler_type) {
    .round_robin => @import("privileged/round_robin.zig"),
    else => @compileError("other scheduler is not supported right now"),
};

pub const ACPI = @import("privileged/acpi.zig");

const bootloader = @import("bootloader");

pub const E9WriterError = error{};
pub const E9Writer = lib.Writer(void, E9WriterError, writeToE9);
pub const writer = E9Writer{ .context = {} };

fn writeToE9(_: void, bytes: []const u8) E9WriterError!usize {
    return arch.io.writeBytes(0xe9, bytes);
}

pub const default_stack_size = 0x4000;

pub const ResourceOwner = enum(u2) {
    bootloader = 0,
    kernel = 1,
    user = 2,
};

pub const CoreSupervisorData = extern struct {
    is_valid: bool,
    next: ?*CoreSupervisorData,
    previous: ?*CoreSupervisorData,
    mdb_root: arch.VirtualAddress(.local),
    init_rootcn: Capabilities.CTE,
    scheduler_state: Scheduler.State,
    kernel_offset: i64,
    irq_in_use: [arch.dispatch_count]u8, // bitmap of handed out caps
    irq_dispatch: [arch.dispatch_count]Capabilities.CTE,
    pending_ram_in_use: u8,
    pending_ram: [4]RAM,
};

const RAM = extern struct {
    base: u64,
    bytes: u64,
};

// pub const RBED = struct {
//     queue_head: ?*CoreDirectorData,
//     queue_tail: ?*CoreDirectorData,
//     // TODO: more stuff
// };

pub const SchedulerType = enum(u8) {
    round_robin,
    rate_based_earliest_deadline,
};

pub const CoreLocality = enum {
    local,
    global,
};

pub const PassId = u32;
pub const CoreId = u8;
pub const CapAddr = u32;

const CTE = Capabilities.CTE;
pub const SpawnState = struct {
    cnodes: struct {
        task: ?*CTE = null,
        seg: ?*CTE = null,
        super: ?*CTE = null,
        physical_address: ?*CTE = null,
        module: ?*CTE = null,
        page: ?*CTE = null,
        base_page: ?*CTE = null,
        early_cnode: ?*CTE = null,
        slot_alloc0: ?*CTE = null,
        slot_alloc1: ?*CTE = null,
        slot_alloc2: ?*CTE = null,
    } = .{},
    slots: struct {
        seg: Capabilities.Slot = 0,
        super: Capabilities.Slot = 0,
        physical_address: Capabilities.Slot = 0,
        module: Capabilities.Slot = 0,
    } = .{},
    argument_page_address: arch.PhysicalAddress(.local) = .null,
};

const panic_logger = lib.log.scoped(.PANIC);

pub fn dumpStackTrace(start_address: usize, frame_pointer: usize) void {
    _ = frame_pointer;
    _ = start_address;
    @panic("TODO: stack trace");
    // if (use_zig_stack_iterator) {
    //     var stack_iterator = common.StackIterator.init(start_address, frame_pointer);
    //     log.err("Stack trace:", .{});
    //     var stack_trace_i: u64 = 0;
    //     while (stack_iterator.next()) |return_address| : (stack_trace_i += 1) {
    //         if (return_address != 0) {
    //             log.err("{}: 0x{x}", .{ stack_trace_i, return_address });
    //         }
    //     }
    // } else {
    //     log.debug("============= STACK TRACE =============", .{});
    //     var ip = start_address;
    //     var stack_trace_depth: u64 = 0;
    //     var maybe_bp = @intToPtr(?[*]usize, frame_pointer);
    //     while (true) {
    //         defer stack_trace_depth += 1;
    //         if (ip != 0) log.debug("{}: 0x{x}", .{ stack_trace_depth, ip });
    //         if (maybe_bp) |bp| {
    //             ip = bp[1];
    //             maybe_bp = @intToPtr(?[*]usize, bp[0]);
    //         } else {
    //             break;
    //         }
    //     }
    //
    //     log.debug("============= STACK TRACE =============", .{});
    // }
}

pub inline fn exitFromQEMU(exit_code: lib.QEMU.ExitCode) noreturn {
    comptime assert(@sizeOf(lib.QEMU.ExitCode) == @sizeOf(u32));
    arch.io.write(u32, lib.QEMU.isa_debug_exit.io_base, @enumToInt(exit_code));

    arch.stopCPU();
}

pub const PageAllocator = extern struct {
    head: ?*Entry,
    allocator: Allocator = .{
        .callbacks = .{
            .allocate = callbackAllocate,
        },
    },
    list_allocator: ListAllocator,

    pub fn callbackAllocate(allocator: *Allocator, size: u64, alignment: u64) Allocator.Allocate.Error!Allocator.Allocate.Result {
        const page_allocator = @fieldParentPtr(PageAllocator, "allocator", allocator);
        if (page_allocator.head == null) {
            @panic("head null");
        }

        var ptr = page_allocator.head;
        while (ptr) |entry| : (ptr = entry.next) {
            if (lib.isAligned(entry.region.size, alignment) and entry.region.size > size) {
                const result = .{
                    .address = entry.region.address.value(),
                    .size = size,
                };
                entry.region.address = entry.region.address.offset(size);
                entry.region.size -= size;

                return result;
            } else {
                const aligned_address = lib.alignForward(entry.region.address.value(), alignment);
                const top = entry.region.address.offset(entry.region.size).value();
                if (aligned_address < top and top - aligned_address > size) {
                    // Split the addresses to obtain the desired result
                    const first_region_size = aligned_address - entry.region.address.value();
                    const first_region_address = entry.region.address;

                    const second_region_address = aligned_address + size;
                    const second_region_size = top - aligned_address + size;

                    const result = .{
                        .address = aligned_address,
                        .size = size,
                    };

                    const new_entry = page_allocator.list_allocator.get();
                    entry.* = .{
                        .region = .{
                            .address = first_region_address,
                            .size = first_region_size,
                        },
                        .next = new_entry,
                    };

                    new_entry.* = .{
                        .region = .{
                            .address = PhysicalAddress(.local).new(second_region_address),
                            .size = second_region_size,
                        },
                        .next = null,
                    };

                    return result;
                }
            }
        }
        @panic("TODO: page allocator callback allocate");
    }

    pub fn allocate(page_allocator: *PageAllocator, size: u64, alignment: u64) Allocator.Allocate.Error!PhysicalMemoryRegion(.local) {
        const result = try page_allocator.allocator.callbacks.allocate(&page_allocator.allocator, size, alignment);
        const region = PhysicalMemoryRegion(.local).new(PhysicalAddress(.local).new(result.address), size);
        return region;
    }

    const ListAllocator = extern struct {
        u: extern union {
            primitive: extern struct {
                backing_4k_page: PhysicalAddress(.local),
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
        region: PhysicalMemoryRegion(.local),
        next: ?*Entry,
    };

    pub inline fn fromBSP(bootloader_information: *bootloader.Information) PageAllocator {
        const memory_map_entries = bootloader_information.getMemoryMapEntries();
        const page_counters = bootloader_information.getPageCounters();

        var total_size: usize = 0;
        const page_shifter = lib.arch.page_shifter(lib.arch.valid_page_sizes[0]);

        for (memory_map_entries, page_counters) |entry, page_counter| {
            if (!lib.isAligned(entry.region.size, lib.arch.valid_page_sizes[0]) or entry.region.address.value() < lib.mb) {
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
                if (!lib.isAligned(entry.region.size, lib.arch.valid_page_sizes[0]) or entry.region.address.value() < lib.mb) continue;

                assert(lib.isAligned(entry_size_left, lib.arch.valid_page_sizes[0]));
                page_counter.* += 1;
                break entry.region.address.offset(occupied_size);
            }
        } else {
            @panic("Can't find bootstraping region");
        };

        var memory_taken: usize = 0;
        var backing_4k_page_memory_allocated: usize = 0;

        var last_entry: ?*Entry = null;
        var first_entry: ?*Entry = null;

        for (memory_map_entries, page_counters) |entry, *page_counter| {
            if (!lib.isAligned(entry.region.size, lib.arch.valid_page_sizes[0]) or entry.region.address.value() < lib.mb) continue;

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

                if (backing_4k_page_memory_allocated >= lib.arch.valid_page_sizes[0]) @panic("Exceeded memory");
                const entry_address = backing_4k_page.offset(backing_4k_page_memory_allocated);
                const new_entry = entry_address.toHigherHalfVirtualAddress().access(*Entry);
                backing_4k_page_memory_allocated += @sizeOf(Entry);

                new_entry.* = .{
                    .region = .{
                        .address = region_descriptor.address.toLocal(),
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
                        .backing_4k_page = backing_4k_page.toLocal(),
                        .allocated = backing_4k_page_memory_allocated,
                    },
                },
                .primitive = true,
            },
        };
        return result;
    }
};

pub fn PhysicalAddress(comptime core_locality: CoreLocality) type {
    return enum(u64) {
        _,
        const PA = @This();

        pub inline fn new(address: u64) PA {
            if (address >= lib.config.cpu_driver_higher_half_address) @panic("Trying to write a higher half virtual address value into a physical address");
            return @intToEnum(PA, address);
        }

        pub inline fn maybeInvalid(address: u64) PA {
            return @intToEnum(PA, address);
        }

        pub inline fn invalid() PA {
            return maybeInvalid(0);
        }

        pub inline fn value(physical_address: PA) u64 {
            return @enumToInt(physical_address);
        }

        pub inline fn toIdentityMappedVirtualAddress(physical_address: PA) VirtualAddress(core_locality) {
            return VirtualAddress(core_locality).new(physical_address.value());
        }

        pub inline fn toHigherHalfVirtualAddress(physical_address: PA) VirtualAddress(core_locality) {
            return physical_address.toIdentityMappedVirtualAddress().offset(lib.config.cpu_driver_higher_half_address);
        }

        pub inline fn addOffset(physical_address: *PA, asked_offset: u64) void {
            physical_address.* = physical_address.offset(asked_offset);
        }

        pub inline fn offset(physical_address: PA, asked_offset: u64) PA {
            return @intToEnum(PA, @enumToInt(physical_address) + asked_offset);
        }

        pub inline fn isAligned(physical_address: PA, alignment: u64) bool {
            const alignment_mask = alignment - 1;
            return physical_address.value() & alignment_mask == 0;
        }

        pub inline fn toLocal(physical_address: PA) PhysicalAddress(.local) {
            return @intToEnum(PhysicalAddress(.local), physical_address.value());
        }
    };
}

pub fn VirtualAddress(comptime core_locality: CoreLocality) type {
    _ = core_locality;

    return enum(u64) {
        null = 0,
        _,

        const VA = @This();

        pub inline fn new(address: u64) VA {
            return @intToEnum(VA, address);
        }

        pub inline fn value(virtual_address: VA) u64 {
            return @enumToInt(virtual_address);
        }

        pub inline fn access(virtual_address: VA, comptime Ptr: type) Ptr {
            return @intToPtr(Ptr, lib.safeArchitectureCast(virtual_address.value()));
        }

        pub inline fn isValid(virtual_address: VA) bool {
            _ = virtual_address;
            return true;
        }

        pub inline fn offset(virtual_address: VA, asked_offset: u64) VA {
            return @intToEnum(VA, virtual_address.value() + asked_offset);
        }

        pub inline fn negativeOffset(virtual_address: VA, asked_offset: u64) VA {
            return @intToEnum(VA, virtual_address.value() - asked_offset);
        }

        pub inline fn toLocal(virtual_address: VA) VirtualAddress(.local) {
            return @intToEnum(VirtualAddress(.local), virtual_address.value());
        }
    };
}

pub fn PhysicalMemoryRegion(comptime core_locality: CoreLocality) type {
    return extern struct {
        address: PhysicalAddress(core_locality),
        size: u64,

        const PMR = @This();

        pub inline fn new(address: PhysicalAddress(core_locality), size: u64) PMR {
            return .{
                .address = address,
                .size = size,
            };
        }

        pub inline fn toIdentityMappedVirtualAddress(physical_memory_region: PMR) VirtualMemoryRegion(core_locality) {
            return .{
                .address = physical_memory_region.address.toIdentityMappedVirtualAddress(),
                .size = physical_memory_region.size,
            };
        }

        pub inline fn toHigherHalfVirtualAddress(physical_memory_region: PMR) VirtualMemoryRegion(core_locality) {
            return .{
                .address = physical_memory_region.address.toHigherHalfVirtualAddress(),
                .size = physical_memory_region.size,
            };
        }

        pub inline fn offset(physical_memory_region: PMR, asked_offset: u64) PMR {
            const address = physical_memory_region.address.offset(asked_offset);
            const size = physical_memory_region.size - asked_offset;

            return .{
                .address = address,
                .size = size,
            };
        }

        pub inline fn takeSlice(physical_memory_region: PMR, asked_size: u64) PMR {
            if (asked_size >= physical_memory_region.size) @panic("asked size is greater than size of region");

            return .{
                .address = physical_memory_region.address,
                .size = asked_size,
            };
        }

        pub inline fn overlaps(physical_memory_region: PMR, other: PMR) bool {
            if (other.address.value() >= physical_memory_region.address.offset(physical_memory_region.size).value()) return false;
            if (other.address.offset(other.size).value() <= physical_memory_region.address.value()) return false;

            const region_inside = other.address.value() >= physical_memory_region.address.value() and other.address.offset(other.size).value() <= physical_memory_region.address.offset(physical_memory_region.size).value();
            const region_overlap_left = other.address.value() <= physical_memory_region.address.value() and other.address.offset(other.size).value() > physical_memory_region.address.value();
            const region_overlap_right = other.address.value() < physical_memory_region.address.offset(physical_memory_region.size).value() and other.address.offset(other.size).value() > physical_memory_region.address.offset(physical_memory_region.size).value();
            return region_inside or region_overlap_left or region_overlap_right;
        }
    };
}

pub fn VirtualMemoryRegion(comptime core_locality: CoreLocality) type {
    const VA = VirtualAddress(core_locality);
    const PMR = PhysicalMemoryRegion(core_locality);
    _ = PMR;

    return extern struct {
        address: VA,
        size: u64,

        const VMR = @This();

        pub inline fn access(virtual_memory_region: VMR, comptime T: type) []T {
            const slice_len = @divExact(virtual_memory_region.size, @sizeOf(T));
            const result = virtual_memory_region.address.access([*]T)[0..lib.safeArchitectureCast(slice_len)];
            return result;
        }
    };
}

const PhysicalAddressSpace = extern struct {
    free_list: List = .{},
    heap_list: List = .{},

    const AllocateError = error{
        not_base_page_aligned,
        out_of_memory,
    };

    const valid_page_sizes = lib.arch.valid_page_sizes;

    pub fn allocate(physical_address_space: *PhysicalAddressSpace, size: u64, page_size: u64) AllocateError!PhysicalMemoryRegion(.local) {
        if (size >= valid_page_sizes[0]) {
            if (!lib.isAligned(size, valid_page_sizes[0])) {
                //log.err("Size is 0x{x} but alignment should be at least 0x{x}", .{ size, valid_page_sizes[0] });
                return AllocateError.not_base_page_aligned;
            }

            var node_ptr = physical_address_space.free_list.first;

            const allocated_region = blk: {
                while (node_ptr) |node| : (node_ptr = node.next) {
                    const result_address = node.descriptor.address.alignedForward(page_size);
                    const size_up = size + result_address.value() - node.descriptor.address.value();
                    if (node.descriptor.size > size_up) {
                        const allocated_region = PhysicalMemoryRegion(.local){
                            .address = result_address,
                            .size = size,
                        };
                        node.descriptor.address.addOffset(size_up);
                        node.descriptor.size -= size_up;

                        break :blk allocated_region;
                    } else if (node.descriptor.size == size_up) {
                        const allocated_region = node.descriptor.offset(size_up - size);
                        if (node.previous) |previous| previous.next = node.next;
                        if (node.next) |next| next.previous = node.previous;
                        if (node_ptr == physical_address_space.free_list.first) physical_address_space.free_list.first = node.next;
                        if (node_ptr == physical_address_space.free_list.last) physical_address_space.free_list.last = node.previous;

                        break :blk allocated_region;
                    }
                }

                return AllocateError.out_of_memory;
            };

            // For now, just zero it out.
            // TODO: in the future, better organization of physical memory to know for sure if the memory still obbeys the upcoming zero flag
            const region_bytes = allocated_region.toHigherHalfVirtualAddress().accessBytes();
            lib.zero(region_bytes);

            return allocated_region;
        } else {
            if (physical_address_space.heap_list.last) |last| {
                if (last.descriptor.size >= size) {
                    const chop = last.descriptor.chop(size);
                    return chop;
                } else {
                    @panic("insufficient size");
                }
            } else {
                var heap_region = try physical_address_space.allocate(valid_page_sizes[1], valid_page_sizes[0]);
                const region_ptr = heap_region.chop(@sizeOf(Region)).address.toHigherHalfVirtualAddress().access(*Region);
                region_ptr.* = .{
                    .descriptor = heap_region,
                };
                physical_address_space.heap_list.append(region_ptr);

                return try physical_address_space.allocate(size, page_size);
            }
        }
    }

    pub fn free(physical_address_space: *PhysicalAddressSpace, size: u64) void {
        _ = physical_address_space;
        _ = size;

        @panic("todo free pages");
    }

    const List = extern struct {
        first: ?*Region = null,
        last: ?*Region = null,
        count: u64 = 0,

        pub fn append(list: *List, node: *Region) void {
            defer list.count += 1;
            if (list.last) |last| {
                last.next = node;
                node.previous = last;
                list.last = node;
            } else {
                list.first = node;
                list.last = node;
            }
        }

        pub fn remove(list: *List, node: *Region) void {
            if (list.first) |first| {
                if (first == node) {
                    list.first = node.next;
                }
            }

            if (list.last) |last| {
                if (last == node) {
                    list.last = node.previous;
                }
            }

            if (node.previous) |previous| {
                previous.next = node.next;
            }

            if (node.next) |next| {
                next.previous = node.previous;
            }
        }
    };

    pub const Region = extern struct {
        descriptor: PhysicalMemoryRegion(.local),
        previous: ?*Region = null,
        next: ?*Region = null,
    };
};

pub const VirtualAddressSpace = extern struct {
    arch: paging.Specific,
    page: Page = .{},
    heap: Heap = .{},
    backing_allocator: *Allocator,
    options: packed struct(u64) {
        user: bool,
        mapped_page_tables: bool,
        log_pages: bool,
        reserved: u61 = 0,
    },

    const Context = extern struct {
        region_base: u64 = 0,
        size: u64 = 0,
    };

    const Page = extern struct {
        allocator: Allocator = .{
            .callbacks = .{
                .allocate = callbackPageAllocate,
            },
        },
        context: Context = .{},
        log: ?*PageAllocator.Entry = null,
        log_count: u64 = 0,
    };

    const Heap = extern struct {
        allocator: Allocator = .{
            .callbacks = .{
                .allocate = callbackHeapAllocate,
            },
        },
        context: Context = .{},
    };

    const VAS = @This();

    pub const paging = switch (lib.cpu.arch) {
        .x86 => arch.x86_64.paging,
        else => arch.current.paging,
    };

    pub const Flags = packed struct(u32) {
        write: bool = false,
        cache_disable: bool = false,
        global: bool = false,
        execute: bool = false,
        user: bool = false,
        reserved: u27 = 0,

        pub inline fn empty() Flags {
            return .{};
        }

        pub inline fn toArchitectureSpecific(flags: Flags, comptime locality: CoreLocality) paging.MemoryFlags {
            return paging.newFlags(flags, locality);
        }
    };

    fn callbackHeapAllocate(allocator: *Allocator, size: u64, alignment: u64) Allocator.Allocate.Error!Allocator.Allocate.Result {
        log.debug("[Heap allocation] Size: {}. Alignment: {}", .{ size, alignment });
        if (lib.cpu.arch != .x86) {
            const virtual_address_space = @fieldParentPtr(VirtualAddressSpace, "heap", @fieldParentPtr(Heap, "allocator", allocator));
            if (virtual_address_space.heap.context.size == 0) {
                const result = try virtual_address_space.backing_allocator.allocateBytes(lib.arch.valid_page_sizes[0], lib.arch.valid_page_sizes[0]);
                virtual_address_space.heap.context = .{
                    .region_base = result.address,
                    .size = result.size,
                };
            }

            if (virtual_address_space.heap.context.size < size) {
                @panic("size");
            }
            if (!lib.isAligned(virtual_address_space.heap.context.region_base, alignment)) {
                @panic("alignment");
            }

            const result = .{
                .address = virtual_address_space.heap.context.region_base,
                .size = size,
            };

            virtual_address_space.heap.context.region_base += size;
            virtual_address_space.heap.context.size -= size;

            return result;
        } else {
            return Allocator.Allocate.Error.OutOfMemory;
        }
    }

    fn callbackPageAllocate(allocator: *Allocator, size: u64, alignment: u64) Allocator.Allocate.Error!Allocator.Allocate.Result {
        const virtual_address_space = @fieldParentPtr(VirtualAddressSpace, "page", @fieldParentPtr(Page, "allocator", allocator));

        if (virtual_address_space.page.context.size == 0) {
            if (alignment > lib.arch.valid_page_sizes[1]) return Allocator.Allocate.Error.OutOfMemory;
            // Try to allocate a bigger bulk so we don't have to use the backing allocator (slower) everytime a page is needed
            const selected_size = @max(size, lib.arch.valid_page_sizes[1]);
            const selected_alignment = @max(alignment, lib.arch.valid_page_sizes[1]);

            const page_bulk_allocation = virtual_address_space.backing_allocator.allocateBytes(selected_size, selected_alignment) catch blk: {
                if (alignment > lib.arch.valid_page_sizes[0]) return Allocator.Allocate.Error.OutOfMemory;
                break :blk try virtual_address_space.backing_allocator.allocateBytes(size, alignment);
            };

            virtual_address_space.page.context = .{
                .region_base = page_bulk_allocation.address,
                .size = page_bulk_allocation.size,
            };

            if (virtual_address_space.options.log_pages) {
                try virtual_address_space.addPage(page_bulk_allocation);
            }
        }

        assert(virtual_address_space.page.context.region_base != 0);

        const allocation_result = .{
            .address = virtual_address_space.page.context.region_base,
            .size = size,
        };

        if (!lib.isAlignedGeneric(u64, allocation_result.address, alignment)) return Allocator.Allocate.Error.OutOfMemory;

        virtual_address_space.page.context.region_base += size;
        virtual_address_space.page.context.size -= size;

        return allocation_result;
    }

    pub fn user(physical_address_space: *PhysicalAddressSpace) VAS {
        // TODO: defer memory free when this produces an error
        // TODO: Maybe consume just the necessary space? We are doing this to avoid branches in the kernel heap allocator
        var virtual_address_space = VAS{
            .arch = undefined,
        };

        paging.init_user(&virtual_address_space, physical_address_space);

        return virtual_address_space;
    }

    pub inline fn makeCurrent(virtual_address_space: *const VAS) void {
        paging.makeCurrent(virtual_address_space);
    }

    pub fn map(virtual_address_space: *VirtualAddressSpace, comptime locality: CoreLocality, asked_physical_address: PhysicalAddress(locality), asked_virtual_address: VirtualAddress(locality), size: u64, general_flags: VirtualAddressSpace.Flags) !void {
        // TODO: use flags
        const flags = general_flags.toArchitectureSpecific(locality);

        log.debug("Mapping 0x{x}-0x{x} to 0x{x}-0x{x}", .{ asked_physical_address.value(), asked_physical_address.offset(size).value(), asked_virtual_address.value(), asked_virtual_address.offset(size).value() });

        // if (!asked_physical_address.isValid()) return Error.invalid_physical;
        // if (!asked_virtual_address.isValid()) return Error.invalid_virtual;
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

        log.debug("Mapping 0x{x} -> 0x{x} for 0x{x} bytes in 0x{x}", .{ asked_virtual_address.value(), asked_physical_address.value(), size, virtual_address_space.arch.cr3.getAddress().value() });

        try paging.map(virtual_address_space, asked_physical_address.value(), asked_virtual_address.value(), size, flags);
    }

    pub inline fn mapDevice(virtual_address_space: *VirtualAddressSpace, asked_physical_address: PhysicalAddress(.global), size: u64) !VirtualAddress(.global) {
        try virtual_address_space.map(.global, asked_physical_address, asked_physical_address.toHigherHalfVirtualAddress(), size, .{
            .write = true,
            .cache_disable = true,
            .global = false,
            .user = true,
        });

        return asked_physical_address.toHigherHalfVirtualAddress();
    }

    pub fn allocatePageTables(virtual_address_space: *VirtualAddressSpace, size: u64, alignment: u64) !PhysicalMemoryRegion(.local) {
        const allocation = try virtual_address_space.page.allocator.allocateBytes(size, alignment);
        return PhysicalMemoryRegion(.local).new(PhysicalAddress(.local).new(allocation.address), size);
    }

    pub fn mapPageTables(virtual_address_space: *VirtualAddressSpace) !void {
        assert(virtual_address_space.options.log_pages);

        log.debug("log count: {}", .{virtual_address_space.page.log_count});
        var maybe_page_table_entry = virtual_address_space.page.log;
        while (maybe_page_table_entry) |page_table_entry| : (maybe_page_table_entry = page_table_entry.next) {
            try virtual_address_space.map(.local, page_table_entry.region.address, page_table_entry.region.address.toIdentityMappedVirtualAddress(), page_table_entry.region.size, .{
                .user = true,
                .write = true,
            });
        }
        assert(virtual_address_space.page.log.?.next == null);
        log.debug("log count: {}", .{virtual_address_space.page.log_count});

        virtual_address_space.options.mapped_page_tables = true;
    }

    fn addPage(virtual_address_space: *VirtualAddressSpace, allocation_result: Allocator.Allocate.Result) !void {
        const new_entry_allocation = try virtual_address_space.heap.allocator.allocateBytes(@sizeOf(PageAllocator.Entry), @alignOf(PageAllocator.Entry));
        const new_entry_region = PhysicalMemoryRegion(.local).new(PhysicalAddress(.local).new(new_entry_allocation.address), new_entry_allocation.size);
        const new_entry = new_entry_region.address.toHigherHalfVirtualAddress().access(*PageAllocator.Entry);
        new_entry.* = .{
            .region = PhysicalMemoryRegion(.local).new(PhysicalAddress(.local).new(allocation_result.address), allocation_result.size),
            .next = virtual_address_space.page.log,
        };

        virtual_address_space.page.log = new_entry;

        virtual_address_space.page.log_count += 1;
    }

    pub inline fn validate(virtual_address_space: *VirtualAddressSpace) !void {
        log.debug("Performing virtual address space validation...", .{});
        try paging.validate(virtual_address_space);
    }

    pub inline fn translateAddress(virtual_address_space: *VirtualAddressSpace, virtual_address: VirtualAddress(.local)) !PhysicalAddress(.local) {
        const physical_address = try paging.translateAddress(virtual_address_space, virtual_address);
        return physical_address;
    }
};

pub const Mapping = extern struct {
    physical: PhysicalAddress(.local) = PhysicalAddress(.local).invalid(),
    virtual: VirtualAddress(.local) = .null,
    size: u64 = 0,
    flags: VirtualAddressSpace.Flags = .{},
    reserved: u32 = 0,
};

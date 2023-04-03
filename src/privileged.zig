// This package provides of privileged data structures and routines to both kernel and bootloaders, for now

const lib = @import("lib");
const assert = lib.assert;
const log = lib.log;
const maxInt = lib.maxInt;
const Allocator = lib.Allocator;

const bootloader = @import("bootloader");

pub const ACPI = @import("privileged/acpi.zig");
pub const arch = @import("privileged/arch.zig");
pub const ELF = @import("privileged/elf.zig");
pub const Executable = @import("privileged/executable.zig");

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

// pub const RBED = struct {
//     queue_head: ?*CoreDirectorData,
//     queue_tail: ?*CoreDirectorData,
//     // TODO: more stuff
// };

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
    list_allocator: ListAllocator,
    total_allocated_size: u32 = 0,

    pub fn allocate(page_allocator: *PageAllocator, size: u64, alignment: u64) Allocator.Allocate.Error!PhysicalMemoryRegion {
        if (page_allocator.head == null) {
            @panic("head null");
        }

        var ptr = page_allocator.head;
        // while (ptr) |entry| : (ptr = entry.next) {
        //     log.debug("Entry before allocate: (Address: 0x{x}. Size: 0x{x})", .{ entry.region.address.value(), entry.region.size });
        // }
        //
        // ptr = page_allocator.head;
        while (ptr) |entry| : (ptr = entry.next) {
            if (lib.isAligned(entry.region.size, alignment) and entry.region.size > size) {
                const result = .{
                    .address = entry.region.address,
                    .size = size,
                };
                entry.region.address = entry.region.address.offset(size);
                entry.region.size -= size;

                page_allocator.total_allocated_size += @intCast(u32, size);
                // log.debug("Allocated 0x{x}", .{size});

                return result;
            }
        }

        ptr = page_allocator.head;

        while (ptr) |entry| : (ptr = entry.next) {
            const aligned_address = lib.alignForward(entry.region.address.value(), alignment);
            const top = entry.region.address.offset(entry.region.size).value();
            if (aligned_address < top and top - aligned_address > size) {
                // log.debug("Found region which we should be splitting: (0x{x}, 0x{x})", .{ entry.region.address.value(), entry.region.size });
                // log.debug("User asked for 0x{x} bytes with alignment 0x{x}", .{ size, alignment });
                // Split the addresses to obtain the desired result
                const first_region_size = aligned_address - entry.region.address.value();
                const first_region_address = entry.region.address;
                const first_region_next = entry.next;

                const second_region_address = aligned_address + size;
                const second_region_size = top - aligned_address + size;

                const result = .{
                    .address = PhysicalAddress.new(aligned_address),
                    .size = size,
                };

                // log.debug("\nFirst region: (Address: 0x{x}. Size: 0x{x}).\nRegion in the middle (allocated): (Address: 0x{x}. Size: 0x{x}).\nSecond region: (Address: 0x{x}. Size: 0x{x})", .{ first_region_address, first_region_size, result.address.value(), result.size, second_region_address, second_region_size });

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
                        .address = PhysicalAddress.new(second_region_address),
                        .size = second_region_size,
                    },
                    .next = first_region_next,
                };
                // log.debug("First entry: (Address: 0x{x}. Size: 0x{x})", .{ entry.region.address.value(), entry.region.size });
                // log.debug("Second entry: (Address: 0x{x}. Size: 0x{x})", .{ new_entry.region.address.value(), new_entry.region.size });

                // page_allocator.total_allocated_size += @intCast(u32, size);
                // log.debug("Allocated 0x{x}", .{size});

                return result;
            }
        }

        log.err("Allocate error. Size: 0x{x}. Alignment: 0x{x}. Total allocated size: 0x{x}", .{ size, alignment, page_allocator.total_allocated_size });
        return Allocator.Allocate.Error.OutOfMemory;
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
};

pub const PhysicalAddress = enum(u64) {
    null = 0,
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

    pub inline fn toIdentityMappedVirtualAddress(physical_address: PA) VirtualAddress {
        return VirtualAddress.new(physical_address.value());
    }

    pub inline fn toHigherHalfVirtualAddress(physical_address: PA) VirtualAddress {
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
};

pub const VirtualAddress = enum(u64) {
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

    pub inline fn toPhysicalAddress(virtual_address: VA) PhysicalAddress {
        assert(virtual_address.value() >= lib.config.cpu_driver_higher_half_address);
        return @intToEnum(PhysicalAddress, virtual_address.value() - lib.config.cpu_driver_higher_half_address);
    }
};

pub const PhysicalMemoryRegion = extern struct {
    address: PhysicalAddress,
    size: u64,

    const PMR = @This();

    pub inline fn new(address: PhysicalAddress, size: u64) PMR {
        return .{
            .address = address,
            .size = size,
        };
    }

    pub inline fn fromSlice(slice: []u8) PMR {
        return .{
            .address = PhysicalAddress.new(@ptrToInt(slice.ptr)),
            .size = slice.len,
        };
    }

    pub inline fn toIdentityMappedVirtualAddress(physical_memory_region: PMR) VirtualMemoryRegion {
        return .{
            .address = physical_memory_region.address.toIdentityMappedVirtualAddress(),
            .size = physical_memory_region.size,
        };
    }

    pub inline fn toHigherHalfVirtualAddress(physical_memory_region: PMR) VirtualMemoryRegion {
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

pub const VirtualMemoryRegion = extern struct {
    address: VirtualAddress,
    size: u64,

    const VMR = @This();

    pub inline fn access(virtual_memory_region: VMR, comptime T: type) []T {
        const slice_len = @divExact(virtual_memory_region.size, @sizeOf(T));
        const result = virtual_memory_region.address.access([*]T)[0..lib.safeArchitectureCast(slice_len)];
        return result;
    }
};

const PhysicalAddressSpace = extern struct {
    free_list: List = .{},
    heap_list: List = .{},

    const AllocateError = error{
        not_base_page_aligned,
        out_of_memory,
    };

    const valid_page_sizes = lib.arch.valid_page_sizes;

    pub fn allocate(physical_address_space: *PhysicalAddressSpace, size: u64, page_size: u64) AllocateError!PhysicalMemoryRegion {
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
                        const allocated_region = PhysicalMemoryRegion{
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
        descriptor: PhysicalMemoryRegion,
        previous: ?*Region = null,
        next: ?*Region = null,
    };
};

pub const Mapping = extern struct {
    physical: PhysicalAddress = PhysicalAddress.invalid(),
    virtual: VirtualAddress = .null,
    size: u64 = 0,
    flags: Flags = .{},
    reserved: u32 = 0,

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

        pub inline fn toArchitectureSpecific(flags: Flags) arch.paging.MemoryFlags {
            return arch.paging.newFlags(flags);
        }
    };
};

pub const PageAllocatorInterface = struct {
    allocate: *const fn (context: ?*anyopaque, size: u64, alignment: u64) Allocator.Allocate.Error!PhysicalMemoryRegion,
    context: ?*anyopaque,
    context_type: ContextType,
    reserved: u32 = 0,

    const ContextType = enum(u32) {
        invalid = 0,
        bootloader = 1,
        cpu = 2,
    };
};

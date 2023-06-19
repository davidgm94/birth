const lib = @import("lib");
const assert = lib.assert;
const Allocator = lib.Allocator;
const enumCount = lib.enumCount;
const log = lib.log.scoped(.capabilities);

const privileged = @import("privileged");
const PhysicalAddress = lib.PhysicalAddress;
const PhysicalMemoryRegion = lib.PhysicalMemoryRegion;
const rise = @import("rise");
const cpu = @import("cpu");

pub const RootDescriptor = extern struct {
    value: *Root,
};

pub const Static = enum {
    cpu,
    boot,
    process,

    pub const count = lib.enumCount(@This());

    pub const Bitmap = @Type(.{
        .Struct = blk: {
            const full_bit_size = @max(@as(comptime_int, 1 << 3), @as(u8, @sizeOf(Static)) << 3);
            break :blk .{
                .layout = .Packed,
                .backing_integer = lib.IntType(.unsigned, full_bit_size),
                .fields = fields: {
                    var fields: []const lib.Type.StructField = &.{};
                    inline for (lib.enumFields(Static)) |static_field| {
                        fields = fields ++ [1]lib.Type.StructField{.{
                            .name = static_field.name,
                            .type = bool,
                            .default_value = null,
                            .is_comptime = false,
                            .alignment = 0,
                        }};
                    }

                    assert(Static.count > 0);
                    assert(@sizeOf(Static) > 0 or Static.count == 1);

                    const padding_type = lib.IntType(.unsigned, full_bit_size - Static.count);

                    fields = fields ++ [1]lib.Type.StructField{.{
                        .name = "reserved",
                        .type = padding_type,
                        .default_value = &@as(padding_type, 0),
                        .is_comptime = false,
                        .alignment = 0,
                    }};
                    break :fields fields;
                },
                .decls = &.{},
                .is_tuple = false,
            };
        },
    });
};

pub const Dynamic = enum {
    io,
    ram, // Barrelfish equivalent: RAM (no PhysAddr)
    cpu_memory, // Barrelfish equivalent: Frame
    page_table, // Barrelfish equivalent: VNode
    // irq_table,
    // device_memory,
    // scheduler,

    pub const Map = extern struct {
        io: IO,
        ram: RAM,
        cpu_memory: CPUMemory,
        page_table: PageTables,

        comptime {
            inline for (lib.fields(Dynamic.Map), lib.fields(Dynamic)) |struct_field, enum_field| {
                assert(lib.equal(u8, enum_field.name, struct_field.name));
            }
        }
    };
};

pub const RAM = extern struct {
    lists: [lib.arch.reverse_valid_page_sizes.len]?*Region = .{null} ** lib.arch.valid_page_sizes.len,

    const AllocateError = error{
        OutOfMemory,
    };

    inline fn getListIndex(size: usize) usize {
        inline for (lib.arch.reverse_valid_page_sizes, 0..) |reverse_page_size, reverse_index| {
            if (size >= reverse_page_size) return reverse_index;
        }

        unreachable;
    }

    pub const Region = extern struct {
        region: PhysicalMemoryRegion,
        next: ?*@This() = null,

        const UnalignedAllocationResult = extern struct {
            wasted: PhysicalMemoryRegion,
            allocated: PhysicalMemoryRegion,
        };

        inline fn allocateUnaligned(free_ram: *Region, size: usize, alignment: usize) ?UnalignedAllocationResult {
            const aligned_region_address = lib.alignForward(usize, free_ram.region.address.value(), alignment);
            const wasted_space = aligned_region_address - free_ram.region.address.value();
            if (free_ram.region.size >= wasted_space + size) {
                const wasted_region = free_ram.region.takeSlice(wasted_space);
                const allocated_region = free_ram.region.takeSlice(size);
                return UnalignedAllocationResult{
                    .wasted = wasted_region,
                    .allocated = allocated_region,
                };
            }

            return null;
        }
    };
};

pub const CPUMemory = extern struct {
    privileged: RAM = .{},
    user: RAM = .{},
    flags: Flags,

    const Flags = packed struct(u64) {
        allocate: bool,
        reserved: u63 = 0,
    };
};

pub const PageTables = extern struct {
    foo: u32 = 0,
};

pub const IO = extern struct {
    debug: bool,
};

pub const Scheduler = extern struct {
    handle: ?*cpu.UserScheduler = null,
    memory: PhysicalMemoryRegion,
};

comptime {
    assert(enumCount(Dynamic) + enumCount(Static) == enumCount(rise.capabilities.Type));
}

pub const Root = extern struct {
    static: Static.Bitmap,
    dynamic: Dynamic.Map,
    scheduler: Scheduler,
    heap: Heap = .{},
    padding: [padding_byte_count]u8 = .{0} ** padding_byte_count,

    const max_alignment = @max(@alignOf(Static.Bitmap), @alignOf(Dynamic.Map), @alignOf(Scheduler), @alignOf(Heap));
    const total_size = lib.alignForward(usize, @sizeOf(Static.Bitmap) + @sizeOf(Dynamic.Map) + @sizeOf(Scheduler) + @sizeOf(Heap), max_alignment);
    const page_aligned_size = lib.alignForward(usize, total_size, lib.arch.valid_page_sizes[0]);
    const padding_byte_count = page_aligned_size - total_size;

    comptime {
        assert(@sizeOf(Root) % lib.arch.valid_page_sizes[0] == 0);
    }

    pub fn copy(root: *Root, other: *Root) void {
        other.static = root.static;
        // TODO:
        other.dynamic = root.dynamic;
    }

    pub inline fn hasPermissions(root: *const Root, comptime capability_type: rise.capabilities.Type, command: rise.capabilities.Command(capability_type)) bool {
        return switch (capability_type) {
            // static capabilities
            inline .cpu,
            .boot,
            .process,
            => |static_capability| @field(root.static, @tagName(static_capability)),
            // dynamic capabilities
            .io => switch (command) {
                .copy, .mint, .retype, .delete, .revoke, .create => unreachable,
                .log => root.dynamic.io.debug,
            },
            .cpu_memory => root.dynamic.cpu_memory.flags.allocate,
            .ram => unreachable,
            .page_table => unreachable,
        };
    }

    pub const AllocateError = error{
        OutOfMemory,
    };

    // Fast path
    pub fn allocatePages(root: *Root, size: usize) AllocateError!PhysicalMemoryRegion {
        assert(size != 0);
        assert(lib.isAligned(size, lib.arch.valid_page_sizes[0]));
        var index = RAM.getListIndex(size);

        const result = blk: {
            while (true) : (index -= 1) {
                const list = root.dynamic.ram.lists[index];
                var iterator = list;

                while (iterator) |free_ram| : (iterator = free_ram.next) {
                    if (free_ram.region.size >= size) {
                        if (free_ram.region.size >= size) {
                            const result = free_ram.region.takeSlice(size);
                            break :blk result;
                        } else {
                            @panic("TODO: cnsume all reigon");
                        }
                    }
                }

                if (index == 0) break;
            }

            return error.OutOfMemory;
        };

        @memset(result.toHigherHalfVirtualAddress().access(u8), 0);

        return result;
    }

    // Slow uncommon path. Use cases:
    // 1. CR3 switch. This is assumed to be privileged, so this function assumes privileged use of the memory
    pub fn allocatePageCustomAlignment(root: *Root, size: usize, alignment: usize) AllocateError!PhysicalMemoryRegion {
        assert(alignment > lib.arch.valid_page_sizes[0] and alignment < lib.arch.valid_page_sizes[1]);

        comptime assert(lib.arch.valid_page_sizes.len == 3);
        var index = RAM.getListIndex(size);

        while (true) : (index -= 1) {
            if (root.dynamic.ram.lists[index]) |smallest_region_list| {
                var iterator: ?*cpu.capabilities.RAM.Region = smallest_region_list;
                while (iterator) |free_ram| : (iterator = free_ram.next) {
                    if (lib.isAligned(free_ram.region.address.value(), alignment)) {
                        if (free_ram.region.size >= size) {
                            const allocated_region = free_ram.region.takeSlice(size);
                            return allocated_region;
                        }
                    } else if (free_ram.allocateUnaligned(size, alignment)) |unaligned_allocation| {
                        try root.addRegion(&root.dynamic.ram, unaligned_allocation.wasted);
                        return unaligned_allocation.allocated;
                    }
                }
            }

            if (index == 0) break;
        }

        return AllocateError.OutOfMemory;
    }

    fn allocateSingle(root: *Root, comptime T: type) AllocateError!*T {
        var iterator = root.heap.first;
        while (iterator) |heap_region| : (iterator = heap_region.next) {
            if (heap_region.alignmentFits(@alignOf(T))) {
                if (heap_region.sizeFits(@sizeOf(T))) {
                    const allocated_region = heap_region.takeRegion(@sizeOf(T));
                    const result = &allocated_region.toHigherHalfVirtualAddress().access(T)[0];
                    return result;
                }
            } else {
                @panic("ELSE");
            }
        }

        const physical_region = try root.allocatePages(lib.arch.valid_page_sizes[0]);
        const heap_region = physical_region.toHigherHalfVirtualAddress().address.access(*Heap.Region);
        const first = root.heap.first;
        heap_region.* = .{
            .descriptor = physical_region.offset(@sizeOf(Heap.Region)),
            .allocated_size = @sizeOf(Heap.Region),
            .next = first,
        };

        root.heap.first = heap_region;

        return try root.allocateSingle(T);
    }

    fn allocateMany(root: *Root, comptime T: type, count: usize) AllocateError![]T {
        _ = count;
        _ = root;

        @panic("TODO many");
    }

    fn addRegion(root: *Root, ram: *RAM, physical_region: PhysicalMemoryRegion) !void {
        const index = RAM.getListIndex(physical_region.size);
        const new_region = try root.allocateSingle(RAM.Region);
        new_region.* = RAM.Region{
            .region = physical_region,
            .next = root.dynamic.ram.lists[index],
        };

        ram.lists[index] = new_region;
    }

    pub const AllocateCPUMemoryOptions = packed struct {
        privileged: bool,
    };

    pub fn allocateCPUMemory(root: *Root, physical_region: PhysicalMemoryRegion, options: AllocateCPUMemoryOptions) !void {
        const ram_region = switch (options.privileged) {
            true => &root.dynamic.cpu_memory.privileged,
            false => &root.dynamic.cpu_memory.user,
        };

        try root.addRegion(ram_region, physical_region);
    }

    pub const Heap = extern struct {
        first: ?*Region = null,

        const AllocateError = error{
            OutOfMemory,
        };

        pub fn new(physical_region: PhysicalMemoryRegion, previous_allocated_size: usize) Heap {
            const allocated_size = previous_allocated_size + @sizeOf(Region);
            assert(physical_region.size > allocated_size);
            const region = physical_region.offset(previous_allocated_size).address.toHigherHalfVirtualAddress().access(*Region);
            region.* = .{
                .descriptor = physical_region,
                .allocated_size = allocated_size,
            };
            return Heap{
                .first = region,
            };
        }

        fn create(heap: *Heap, comptime T: type) Heap.AllocateError!*T {
            const result = try heap.allocate(T, 1);
            return &result[0];
        }

        fn allocate(heap: *Heap, comptime T: type, count: usize) Heap.AllocateError![]T {
            var iterator = heap.first;
            while (iterator) |heap_region| {
                const allocation = heap_region.allocate(T, count) catch continue;
                return allocation;
            }
            @panic("TODO: allocate");
        }

        const Region = extern struct {
            descriptor: PhysicalMemoryRegion,
            allocated_size: usize,
            next: ?*Region = null,

            inline fn getFreeRegion(region: Region) PhysicalMemoryRegion {
                const free_region = region.descriptor.offset(region.allocated_size);
                assert(free_region.size > 0);
                return free_region;
            }

            const AllocateError = error{
                OutOfMemory,
            };

            fn takeRegion(region: *Region, size: usize) PhysicalMemoryRegion {
                var free_region = region.getFreeRegion();
                assert(free_region.size >= size);
                const allocated_region = free_region.takeSlice(size);
                region.allocated_size += size;
                return allocated_region;
            }

            fn allocate(region: *Region, comptime T: type, count: usize) Region.AllocateError![]T {
                const free_region = region.getFreeRegion();
                _ = free_region;
                _ = count;
                @panic("TODO: region allocate");
            }

            fn create(region: *Region, comptime T: type) Region.AllocateError!*T {
                const result = try region.allocate(T, 1);
                return &result[0];
            }

            inline fn canAllocateDirectly(region: Region, size: usize, alignment: usize) bool {
                const alignment_fits = region.alignmentFits(alignment);
                const size_fits = region.sizeFits(size);
                return alignment_fits and size_fits;
            }

            inline fn canAllocateSplitting(region: Region, size: usize, alignment: usize) bool {
                const free_region = region.getFreeRegion();
                const aligned_region_address = lib.alignForward(usize, free_region.address.value(), alignment);
                const wasted_space = aligned_region_address - free_region.address.value();
                log.warn("Wasted space: {} bytes", .{wasted_space});
                _ = size;
                @panic("TODO: canAllocateSplitting");
            }

            inline fn sizeFits(region: Region, size: usize) bool {
                return region.descriptor.size - region.allocated_size >= size;
            }

            inline fn alignmentFits(region: Region, alignment: usize) bool {
                const result = lib.isAligned(region.getFreeRegion().address.value(), alignment);
                return result;
            }
        };
    };
};

pub const RootPageTableEntry = extern struct {
    address: PhysicalAddress,
};

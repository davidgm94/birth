pub const BIOS = @import("bootloader/bios.zig");
pub const UEFI = @import("bootloader/uefi.zig");
pub const limine = @import("bootloader/limine/spec.zig");

const lib = @import("lib.zig");
const assert = lib.assert;
const Allocator = lib.Allocator;
const Protocol = lib.Bootloader.Protocol;

const privileged = @import("privileged.zig");
const AddressInterface = privileged.Address.Interface(u64);
const PhysicalAddress = AddressInterface.PhysicalAddress;
const VirtualAddress = AddressInterface.VirtualAddress;
const PhysicalMemoryRegion = AddressInterface.PhysicalMemoryRegion;
const VirtualMemoryRegion = AddressInterface.VirtualMemoryRegion;

pub const Information = extern struct {
    protocol: lib.Bootloader.Protocol,
    bootloader: lib.Bootloader,
    size: u32,
    extra_size_after_aligned_end: u32,
    entry_point: u64,
    page_allocator: Allocator = .{
        .callbacks = .{
            .allocate = pageAllocate,
        },
    },
    heap: Heap,
    cpu_driver_mappings: CPUDriverMappings,
    offsets: Offsets,
    architecture: switch (lib.cpu.arch) {
        .x86, .x86_64 => extern struct {
            rsdp_address: u64,
        },
        else => @compileError("Architecture not supported"),
    },

    pub const Offsets = extern struct {
        page_counters: Offset = .{},
        memory_map: Offset = .{},
        stack: Offset = .{},
    };

    const Offset = extern struct {
        offset: u32 = 0,
        size: u32 = 0,
        base_element_size: u32 = 0,
        len: u32 = 0,
    };

    // TODO:
    const PA = PhysicalAddress(.global);
    const PMR = PhysicalMemoryRegion(.global);

    const Pages = extern struct {};

    const Heap = extern struct {
        allocator: Allocator = .{
            .callbacks = .{
                .allocate = heapAllocate,
            },
        },
        regions: [6]PMR = lib.zeroes([6]PMR),
    };

    pub inline fn getRegionFromOffset(information: *Information, comptime offset_field: []const u8) VirtualMemoryRegion(.local) {
        const offset = @field(information.offsets, offset_field);
        return .{
            .address = VirtualAddress(.local).new(@ptrToInt(information) + offset.offset),
            .size = offset.size,
        };
    }

    pub fn getMemoryMapEntries(information: *Information) []MemoryMapEntry {
        return information.getRegionFromOffset("memory_map").access(MemoryMapEntry);
    }

    pub fn getPageCounters(information: *Information) []u32 {
        return information.getRegionFromOffset("page_counters").access(u32);
    }

    pub fn getStructAlignedSize() usize {
        return lib.alignForward(@sizeOf(Information), lib.arch.valid_page_sizes[0]);
    }

    pub fn isSizeRight(information: *const Information) bool {
        var size: usize = 0;
        size += lib.alignForward(@sizeOf(Information), lib.arch.valid_page_sizes[0]);
        var offset_size: usize = 0;

        if (information.offsets.memory_map.base_element_size != @sizeOf(MemoryMapEntry)) return false;
        if (information.offsets.memory_map.len * @sizeOf(MemoryMapEntry) != information.offsets.memory_map.size) return false;
        inline for (lib.fields(Information.Offsets)) |field| {
            const name = field.name;
            const field_value = @field(information.offsets, name);
            offset_size += field_value.size;
        }

        offset_size = lib.alignForward(offset_size, lib.arch.valid_page_sizes[0]);
        size += offset_size;

        lib.log.debug("Size: 0x{x}. Registered size: 0x{x}. Extra: 0x{x}. Registered extra: 0x{x}", .{ size, information.size, offset_size, information.extra_size_after_aligned_end });

        return information.size == size and information.extra_size_after_aligned_end == offset_size;
    }

    inline fn allocateChunk(information: *Information, allocated_size: *usize, comptime offset_field: []const u8, size: u32, base_element_size: u32, len: u32) void {
        if (allocated_size.* + size > information.extra_size_after_aligned_end) @panic("size exceeded");
        const offset = allocated_size.* + getStructAlignedSize();

        @field(information.offsets, offset_field).offset = offset;
        @field(information.offsets, offset_field).size = size;
        @field(information.offsets, offset_field).base_element_size = base_element_size;
        @field(information.offsets, offset_field).len = len;

        allocated_size.* = allocated_size.* + size;
    }

    pub fn fromBIOS(rsdp_address: u64, memory_map_entry_count: usize, stack_size: usize) !*Information {
        var iterator = BIOS.E820Iterator{};

        const memory_map_size = memory_map_entry_count * @sizeOf(MemoryMapEntry);
        const page_counter_size = memory_map_entry_count * @sizeOf(u32);
        const extra_size_after_aligned_end = stack_size + memory_map_size + page_counter_size;
        const aligned_extra_size_after_aligned_end = lib.alignForward(stack_size + memory_map_size + page_counter_size, lib.arch.valid_page_sizes[0]);
        const aligned_struct_size = getStructAlignedSize();
        const size_to_allocate = aligned_struct_size + aligned_extra_size_after_aligned_end;

        while (iterator.next()) |entry| {
            if (!entry.descriptor.isLowMemory() and entry.descriptor.region.size > size_to_allocate) {
                const bootloader_information_region = entry.descriptor.region.takeSlice(@sizeOf(Information));
                const result = bootloader_information_region.address.toIdentityMappedVirtualAddress().access(*Information);
                result.* = .{
                    .protocol = .bios,
                    .bootloader = .rise,
                    .size = size_to_allocate,
                    .extra_size_after_aligned_end = aligned_extra_size_after_aligned_end,
                    .entry_point = 0,
                    .heap = .{},
                    .cpu_driver_mappings = .{},
                    .offsets = .{},
                    .architecture = .{
                        .rsdp_address = rsdp_address,
                    },
                };

                var allocated_size: usize = 0;
                result.allocateChunk(&allocated_size, "stack", stack_size, @sizeOf(u8), @divExact(stack_size, @sizeOf(u8)));
                result.allocateChunk(&allocated_size, "memory_map", memory_map_size, @sizeOf(MemoryMapEntry), memory_map_entry_count);
                result.allocateChunk(&allocated_size, "page_counters", page_counter_size, @sizeOf(u32), memory_map_entry_count);

                if (allocated_size != extra_size_after_aligned_end) @panic("Offset allocation size must matched bootloader allocated size");

                const page_counters = result.getPageCounters();
                for (page_counters) |*page_counter| {
                    page_counter.* = 0;
                }

                page_counters[entry.index] = size_to_allocate;

                const memory_map_entries = result.getMemoryMapEntries();
                BIOS.fetchMemoryEntries(memory_map_entries);

                return result;
            }
        }

        return Allocator.Allocate.Error.OutOfMemory;
    }

    pub fn pageAllocate(allocator: *Allocator, size: u64, alignment: u64) Allocator.Allocate.Error!Allocator.Allocate.Result {
        const bootloader_information = @fieldParentPtr(Information, "page_allocator", allocator);

        if (size & lib.arch.page_mask(lib.arch.valid_page_sizes[0]) != 0) return Allocator.Allocate.Error.OutOfMemory;
        if (alignment & lib.arch.page_mask(lib.arch.valid_page_sizes[0]) != 0) return Allocator.Allocate.Error.OutOfMemory;
        const four_kb_pages = @intCast(u32, @divExact(size, lib.arch.valid_page_sizes[0]));

        const entries = bootloader_information.getMemoryMapEntries();
        const page_counters = bootloader_information.getPageCounters();

        for (entries) |entry, entry_index| {
            const busy_size = page_counters[entry_index] * lib.arch.valid_page_sizes[0];
            const size_left = entry.region.size - busy_size;
            if (entry.type == .usable and size_left > size) {
                if (entry.region.address.isAligned(alignment)) {
                    const result = Allocator.Allocate.Result{
                        .address = entry.region.address.offset(busy_size).value(),
                        .size = size,
                    };

                    page_counters[entry_index] += four_kb_pages;

                    return result;
                }
            }
        }

        return Allocator.Allocate.Error.OutOfMemory;
    }

    pub fn heapAllocate(allocator: *Allocator, size: u64, alignment: u64) Allocator.Allocate.Error!Allocator.Allocate.Result {
        const bootloader_information = @fieldParentPtr(Information, "heap", @fieldParentPtr(Heap, "allocator", allocator));
        for (bootloader_information.heap.regions) |*region| {
            if (region.size > size) {
                const result = .{
                    .address = region.address.value(),
                    .size = size,
                };
                region.size -= size;
                region.address.addOffset(size);
                return result;
            }
        }
        const size_to_page_allocate = lib.alignForwardGeneric(u64, size, lib.arch.valid_page_sizes[0]);
        for (bootloader_information.heap.regions) |*region| {
            if (region.size == 0) {
                const allocated_region = try bootloader_information.page_allocator.allocateBytes(size_to_page_allocate, lib.arch.valid_page_sizes[0]);
                region.* = .{
                    .address = PA.new(allocated_region.address),
                    .size = allocated_region.size,
                };
                const result = .{
                    .address = region.address.value(),
                    .size = size,
                };
                region.address.addOffset(size);
                region.size -= size;
                return result;
            }
        }

        _ = alignment;
        @panic("todo: heap allocate");
    }
};

pub const CPUDriverMappings = extern struct {
    text: Mapping = .{},
    data: Mapping = .{},
    rodata: Mapping = .{},

    const Mapping = extern struct {
        physical: PhysicalAddress(.local) = PhysicalAddress(.local).invalid(),
        virtual: VirtualAddress(.local) = .null,
        size: u64 = 0,
    };
};

const current_protocol: ?Protocol = switch (lib.cpu.arch) {
    .x86 => switch (lib.os) {
        // Using BIOS
        .freestanding => .bios,
        // Using UEFI
        .uefi => .uefi,
        else => @compileError("Unexpected operating system"),
    },
    .x86_64 => switch (lib.os) {
        // CPU driver
        .freestanding => null,
        // Using UEFI
        .uefi => .uefi,
        else => @compileError("Unexpected operating system"),
    },
    else => @compileError("Architecture not supported"),
};

fn EntryType(comptime protocol: Protocol) type {
    return switch (protocol) {
        .bios => BIOS.MemoryMapEntry,
        .uefi => UEFI.MemoryDescriptor,
    };
}

pub const MemoryMapEntry = extern struct {
    region: PhysicalMemoryRegion(.global),
    type: Type,

    const Type = enum(u64) {
        usable = 0,
        reserved = 1,
        bad_memory = 2,
    };

    comptime {
        assert(@sizeOf(MemoryMapEntry) == @sizeOf(u64) * 3);
    }
};

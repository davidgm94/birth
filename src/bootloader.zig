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
    memory_map: MemoryMap,
    // Page allocator
    page: Pages,
    heap: Heap,
    offsets: Offsets,
    architecture: switch (lib.cpu.arch) {
        .x86, .x86_64 => extern struct {
            rsdp_address: u64,
        },
        else => @compileError("Architecture not supported"),
    },

    const Offsets = extern struct {
        size_counters: Offset = .{},
        memory_map: Offset = .{},
    };

    const Offset = extern struct {
        offset: u32 = 0,
        size: u32 = 0,
    };

    // TODO:
    const PA = PhysicalAddress(.global);
    const PMR = PhysicalMemoryRegion(.global);

    const Pages = extern struct {
        allocator: Allocator = .{
            .callbacks = .{
                .allocate = pageAllocate,
            },
        },
    };

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

    pub fn getStructAlignedSize() usize {
        return lib.alignForward(@sizeOf(Information), lib.arch.valid_page_sizes[0]);
    }

    pub fn fromBIOS(rsdp_address: u64, memory_map_entry_count: usize, stack_size: usize) !*Information {
        var iterator = BIOS.E820Iterator{};
        const aligned_struct_size = getStructAlignedSize();
        const extra_size_after_aligned_end = memory_map_entry_count * @sizeOf(MemoryMapEntry) + memory_map_entry_count * @sizeOf(u32) + stack_size;
        const size_to_allocate = aligned_struct_size + extra_size_after_aligned_end;

        while (iterator.next()) |entry| {
            if (!entry.isLowMemory() and entry.region.size > size_to_allocate) {
                const bootloader_information_region = entry.region.takeSlice(@sizeOf(Information));
                const result = bootloader_information_region.address.toIdentityMappedVirtualAddress().access(*Information);
                result.* = .{
                    .protocol = .bios,
                    .bootloader = .rise,
                    .size = size_to_allocate,
                    .extra_size_after_aligned_end = extra_size_after_aligned_end,
                    .entry_point = 0,
                    .memory_map = .{},
                    .page = .{},
                    .heap = .{},
                    .offsets = .{},
                    .architecture = .{
                        .rsdp_address = rsdp_address,
                    },
                };

                @panic("TODO: BIOS");

                // result.page.counters[iterator.index] = lib.alignForward(@sizeOf(Information), lib.arch.valid_page_sizes[0]) / lib.arch.valid_page_sizes[0];
                // BIOS.fetchMemoryEntries(&result.memory_map);
                //
                // result.cpu_driver_mappings.stack.size = 0x4000;
                // const stack_allocation = try result.page.allocator.allocateBytes(result.cpu_driver_mappings.stack.size, lib.arch.valid_page_sizes[0]);
                // result.cpu_driver_mappings.stack.physical = PhysicalAddress(.local).new(stack_allocation.address);
                // result.cpu_driver_mappings.stack.virtual = result.cpu_driver_mappings.stack.physical.toIdentityMappedVirtualAddress();
                //
                // return result;
            }
        }

        return Allocator.Allocate.Error.OutOfMemory;
    }

    pub fn pageAllocate(allocator: *Allocator, size: u64, alignment: u64) Allocator.Allocate.Error!Allocator.Allocate.Result {
        const bootloader_information = @fieldParentPtr(Information, "page", @fieldParentPtr(Pages, "allocator", allocator));
        _ = bootloader_information;

        if (size & lib.arch.page_mask(lib.arch.valid_page_sizes[0]) != 0) return Allocator.Allocate.Error.OutOfMemory;
        if (alignment & lib.arch.page_mask(lib.arch.valid_page_sizes[0]) != 0) return Allocator.Allocate.Error.OutOfMemory;
        const four_kb_pages = @intCast(u32, @divExact(size, lib.arch.valid_page_sizes[0]));
        _ = four_kb_pages;

        if (current_protocol) |protocol| {
            _ = protocol;
            @panic("TODO: pageAllocate");
            // const entries = bootloader_information.memory_map.getNativeEntries(protocol);
            // for (entries) |entry, entry_index| {
            //     const busy_size = bootloader_information.page.counters[entry_index] * lib.arch.valid_page_sizes[0];
            //     const size_left = entry.region.size - busy_size;
            //     if (entry.isUsable() and size_left > size) {
            //         if (entry.region.address.isAligned(alignment)) {
            //             const result = Allocator.Allocate.Result{
            //                 .address = entry.region.address.offset(busy_size).value(),
            //                 .size = size,
            //             };
            //
            //             bootloader_information.page.counters[entry_index] += four_kb_pages;
            //
            //             return result;
            //         }
            //     }
            // }
            //
            // return Allocator.Allocate.Error.OutOfMemory;
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
                const allocated_region = try bootloader_information.page.allocator.allocateBytes(size_to_page_allocate, lib.arch.valid_page_sizes[0]);
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

pub const MemoryMap = extern struct {
    buffer: [size]u8 = [1]u8{0} ** size,
    entry_count: u32 = 0,

    pub const size = 48 * 128;

    const BIOSMemoryMap = extern struct {
        descriptors: [entry_count]BIOS.MemoryMapEntry = [1]BIOS.MemoryMapEntry{lib.zeroes(BIOS.MemoryMapEntry)} ** entry_count,
    };
    const UEFIMemoryMap = extern struct {
        descriptors: [entry_count]UEFI.MemoryDescriptor = [1]UEFI.MemoryDescriptor{lib.zeroes(UEFI.MemoryDescriptor)} ** entry_count,
        descriptor_size: u32 = @sizeOf(UEFI.MemoryDescriptor),
        descriptor_version: u32 = 1,
    };

    const entry_count = 128;

    pub fn getNativeEntries(memory_map: *MemoryMap, comptime protocol: Protocol) []const EntryType(protocol) {
        return switch (protocol) {
            .bios => @ptrCast([*]const BIOS.MemoryMapEntry, @alignCast(@alignOf(BIOS.MemoryMapEntry), &memory_map.buffer))[0..entry_count],
            .uefi => @panic("todo: uefi native iterator"),
        };
    }

    pub fn getEntry(memory_map: *MemoryMap, comptime protocol: Protocol, index: usize) *EntryType(protocol) {
        return switch (protocol) {
            .bios => &@ptrCast([*]BIOS.MemoryMapEntry, @alignCast(@alignOf(BIOS.MemoryMapEntry), &memory_map.buffer[index * @sizeOf(BIOS.MemoryMapEntry)]))[0],
            .uefi => @panic("todo: uefi native iterator"),
        };
    }

    fn EntryIterator(comptime protocol: Protocol) type {
        const Entry = EntryType(protocol);
        return struct {
            entries: []const Entry,
            index: usize = 0,

            const Iterator = @This();
        };
    }
};

fn EntryType(comptime protocol: Protocol) type {
    return switch (protocol) {
        .bios => BIOS.MemoryMapEntry,
        .uefi => UEFI.MemoryDescriptor,
    };
}

pub const MemoryMapEntry = extern struct {
    region: PhysicalMemoryRegion(.local),
    type: Type,

    const Type = enum(u64) {
        usable = 0,
        reserved = 1,
    };

    comptime {
        assert(@sizeOf(MemoryMapEntry) == @sizeOf(u64) * 3);
    }
};

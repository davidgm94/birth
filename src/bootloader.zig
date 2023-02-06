pub const BIOS = @import("bootloader/bios.zig");
pub const UEFI = @import("bootloader/uefi.zig");

const lib = @import("lib.zig");
const Allocator = lib.Allocator;
const Protocol = lib.Bootloader.Protocol;

const privileged = @import("privileged.zig");
const AddressInterface = privileged.Address.Interface;

pub const Information = extern struct {
    protocol: lib.Bootloader.Protocol,
    bootloader: lib.Bootloader,
    size: u32 = @sizeOf(Information),
    entry_point: u64,
    memory_map: MemoryMap,
    // Page allocator
    page: Pages,
    heap: Heap,
    cpu_driver_mappings: CPUDriverMappings,
    architecture: switch (lib.cpu.arch) {
        .x86, .x86_64 => extern struct {
            rsdp_address: u64,
        },
        else => @compileError("Architecture not supported"),
    },

    // TODO:
    const AI = AddressInterface(u64);
    const PA = AI.PhysicalAddress(.global);
    const PMR = AI.PhysicalMemoryRegion(.global);

    const Pages = extern struct {
        allocator: Allocator = .{
            .callbacks = .{
                .allocate = pageAllocate,
            },
        },
        counters: [MemoryMap.entry_count]u32 = [1]u32{0} ** MemoryMap.entry_count,
    };

    const Heap = extern struct {
        allocator: Allocator = .{
            .callbacks = .{
                .allocate = heapAllocate,
            },
        },
        regions: [6]PMR = lib.zeroes([6]PMR),
    };

    pub fn fromBIOS(rsdp_address: u64) !*Information {
        var iterator = BIOS.E820Iterator{};
        while (iterator.next()) |entry| {
            if (!entry.isLowMemory() and entry.region.size > @sizeOf(Information)) {
                const bootloader_information_region = entry.region.takeSlice(@sizeOf(Information));
                const result = bootloader_information_region.address.toIdentityMappedVirtualAddress().access(*Information);
                result.* = .{
                    .protocol = .bios,
                    .bootloader = .rise,
                    .entry_point = 0,
                    .memory_map = .{},
                    .page = .{},
                    .heap = .{},
                    .cpu_driver_mappings = .{},
                    .architecture = .{
                        .rsdp_address = rsdp_address,
                    },
                };

                result.page.counters[iterator.index] = lib.alignForward(@sizeOf(Information), lib.arch.valid_page_sizes[0]) / lib.arch.valid_page_sizes[0];
                BIOS.fetchMemoryEntries(&result.memory_map);

                result.cpu_driver_mappings.stack.size = 0x4000;
                const stack_allocation = try result.page.allocator.allocateBytes(result.cpu_driver_mappings.stack.size, lib.arch.valid_page_sizes[0]);
                result.cpu_driver_mappings.stack.physical = AddressInterface(u64).PhysicalAddress(.local).new(stack_allocation.address);
                result.cpu_driver_mappings.stack.virtual = result.cpu_driver_mappings.stack.physical.toIdentityMappedVirtualAddress();

                return result;
            }
        }

        return Allocator.Allocate.Error.OutOfMemory;
    }

    pub fn pageAllocate(allocator: *Allocator, size: u64, alignment: u64) Allocator.Allocate.Error!Allocator.Allocate.Result {
        const bootloader_information = @fieldParentPtr(Information, "page", @fieldParentPtr(Pages, "allocator", allocator));

        if (size & lib.arch.page_mask(lib.arch.valid_page_sizes[0]) != 0) return Allocator.Allocate.Error.OutOfMemory;
        if (alignment & lib.arch.page_mask(lib.arch.valid_page_sizes[0]) != 0) return Allocator.Allocate.Error.OutOfMemory;
        const four_kb_pages = @intCast(u32, @divExact(size, lib.arch.valid_page_sizes[0]));

        if (current_protocol) |protocol| {
            const entries = bootloader_information.memory_map.getNativeEntries(protocol);
            for (entries) |entry, entry_index| {
                const busy_size = bootloader_information.page.counters[entry_index] * lib.arch.valid_page_sizes[0];
                const size_left = entry.region.size - busy_size;
                if (entry.isUsable() and size_left > size) {
                    if (entry.region.address.isAligned(alignment)) {
                        const result = Allocator.Allocate.Result{
                            .address = entry.region.address.offset(busy_size).value(),
                            .size = size,
                        };

                        bootloader_information.page.counters[entry_index] += four_kb_pages;

                        return result;
                    }
                }
            }

            return Allocator.Allocate.Error.OutOfMemory;
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

pub const CPUDriverMappings = extern struct {
    text: Mapping = .{},
    data: Mapping = .{},
    rodata: Mapping = .{},
    stack: Mapping = .{},

    const Mapping = extern struct {
        const AI = AddressInterface(u64);
        const PA = AI.PhysicalAddress(.local);
        const VA = AI.VirtualAddress(.local);

        physical: PA = PA.invalid(),
        virtual: VA = .null,
        size: u64 = 0,
    };
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

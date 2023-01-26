pub const BIOS = @import("bootloader/bios.zig");
pub const UEFI = @import("bootloader/uefi.zig");

const lib = @import("lib");
const Allocator = lib.Allocator;
const Protocol = lib.Bootloader.Protocol;

const privileged = @import("privileged");

const current_protocol: ?Protocol = switch (lib.cpu.arch) {
    .x86 => switch (lib.os) {
        // Using BIOS
        .freestanding => .bios,
        // Using UEFI
        .uefi => .uefi,
        else => @compileError("Unexpected operating system"),
    },
    .x86_64 => switch (lib.os) {
        // Kernel
        .freestanding => null,
        // Using UEFI
        .uefi => .uefi,
        else => @compileError("Unexpected operating system"),
    },
    else => @compileError("Architecture not supported"),
};

const AddressInterface = privileged.Address.Interface;

pub const Information = extern struct {
    protocol: lib.Bootloader.Protocol,
    memory_map: MemoryMap,
    // Page allocator
    pages: Pages,
    heap: Heap,
    regions: [6]PMR = lib.zeroes([6]PMR),

    const PMR = AddressInterface(u64).PhysicalMemoryRegion(.global);

    const Pages = extern struct {
        allocator: Allocator = .{
            .callback_allocate = pageAllocate,
        },
        size_counters: [MemoryMap.entry_count]u32 = [1]u32{0} ** MemoryMap.entry_count,
    };

    const Heap = extern struct {
        allocator: Allocator = .{
            .callback_allocate = heapAllocate,
        },
    };

    const GetError = error{
        out_of_memory,
    };

    pub fn fromBIOS() GetError!*Information {
        var iterator = BIOS.E820Iterator{};
        while (iterator.next()) |entry| {
            if (!entry.isLowMemory() and entry.region.size > @sizeOf(Information)) {
                const bootloader_information_region = entry.region.takeSlice(@sizeOf(Information));
                const result = bootloader_information_region.address.toIdentityMappedVirtualAddress().access(*Information);
                result.* = .{
                    .protocol = .bios,
                    .memory_map = .{
                        .native = .{
                            .bios = .{},
                        },
                    },
                    .pages = .{},
                    .heap = .{},
                };
                result.pages.size_counters[iterator.index] = @sizeOf(Information);
                BIOS.fetchMemoryEntries(&result.memory_map);
                return result;
            }
        }

        return GetError.out_of_memory;
    }

    pub fn pageAllocate(allocator: *Allocator, size: u64, alignment: u64) Allocator.Allocate.Error!Allocator.Allocate.Result {
        _ = alignment;
        _ = size;
        const memory_manager = @fieldParentPtr(MemoryMapManager, "allocator", allocator);
        _ = memory_manager;

        if (current_protocol) |protocol| {
            switch (protocol) {
                .bios => @panic("using bios"),
                .uefi => @panic("using uefi"),
            }
        }

        return Allocator.Allocate.Error.OutOfMemory;
    }

    pub fn heapAllocate(allocator: *Allocator, size: u64, alignment: u64) Allocator.Allocate.Error!Allocator.Allocate.Result {
        _ = alignment;
        _ = size;
        _ = allocator;
        @panic("todo: heap allocate");
    }
};

pub const MemoryMap = extern struct {
    native: extern union {
        uefi: UEFIMemoryMap,
        bios: BIOSMemoryMap,
    },
    entry_count: u32 = 0,

    const BIOSMemoryMap = extern struct {
        descriptors: [entry_count]BIOS.MemoryMapEntry = [1]BIOS.MemoryMapEntry{lib.zeroes(BIOS.MemoryMapEntry)} ** entry_count,
    };
    const UEFIMemoryMap = extern struct {
        descriptors: [entry_count]UEFI.MemoryDescriptor = [1]UEFI.MemoryDescriptor{lib.zeroes(UEFI.MemoryDescriptor)} ** entry_count,
        descriptor_size: u32 = @sizeOf(UEFI.MemoryDescriptor),
        descriptor_version: u32 = 1,
    };

    const entry_count = 128;

    pub fn getNativeIterator(memory_map: *MemoryMap, comptime protocol: Protocol) EntryIterator(protocol) {
        _ = memory_map;
        return EntryIterator(protocol){};
    }

    fn EntryIterator(comptime protocol: Protocol) type {
        _ = protocol;
        return struct {};
    }
};

const MemoryMapManager = extern struct {
    memory_map: MemoryMap,
    size_counters: [MemoryMap.entry_count]u32,
    allocator: Allocator,
};

// pub fn MemoryManager(comptime architecture: lib.Target.Cpu.Arch) type {
//     return extern struct {
//         memory_map: MemoryMap(architecture),
//         size_counters_region: PMR,
//         allocator: Allocator,
//
//         const PA = addresses.PhysicalAddress(architecture, .global);
//         const PMR = addresses.PhysicalMemoryRegion(architecture, .global);
//         const VMR = addresses.VirtualMemoryRegion(architecture, .global);
//         const MM = @This();
//
//
//         pub fn Interface(comptime loader_protocol: LoaderProtocol) type {
//             return extern struct {
//                 const EntryType = switch (loader_protocol) {
//                     .bios => bootloader.BIOS.MemoryMapEntry,
//                     .uefi => bootloader.UEFI.MemoryDescriptor,
//                 };
//
//                 const GenericEntry = extern struct {
//                     region: PMR,
//                     usable: bool,
//                 };
//
//                 fn getGenericEntry(entry: anytype) GenericEntry {
//                     return switch (@TypeOf(entry)) {
//                         bootloader.BIOS.MemoryMapEntry => .{
//                             .region = entry.region,
//                             .usable = entry.region.address.value() >= 1 * lib.mb,
//                         },
//                         bootloader.UEFI.MemoryDescriptor => .{
//                             .region = PMR{
//                                 .address = PA.new(entry.physical_start),
//                                 .size = entry.number_of_pages * lib.arch.valid_page_sizes[0],
//                             },
//                             .usable = @panic("UEFI usable"),
//                         },
//                         else => @compileError("Type not admitted"),
//                     };
//                 }
//
//
//                 pub fn allocate(memory_manager: MemoryManager(architecture), asked_size: u64, asked_alignment: u64) !PMR {
//                     // TODO: satisfy alignment
//                     if (asked_size & lib.arch.page_mask(lib.arch.valid_page_sizes[0]) != 0) @panic("not page-aligned allocate");
//
//                     const four_kb_pages = @divExact(asked_size, lib.arch.valid_page_sizes[0]);
//
//                     const entries = memory_manager.memory_map.getEntries(EntryType);
//                     for (entries) |entry, entry_index| {
//                         const generic_entry = getGenericEntry(entry);
//                         const busy_size = memory_manager.getSizeCounters()[entry_index] * lib.arch.valid_page_sizes[0];
//                         const size_left = generic_entry.region.size - busy_size;
//
//                         if (generic_entry.usable and size_left > asked_size) {
//                             if (generic_entry.region.address.isAligned(asked_alignment)) {
//                                 const result = .{
//                                     .address = generic_entry.region.address.offset(busy_size),
//                                     .size = asked_size,
//                                 };
//
//                                 memory_manager.getSizeCounters()[entry_index] += four_kb_pages;
//
//                                 return result;
//                             }
//                         }
//                     }
//
//                     return Allocator.Allocate.Error.OutOfMemory;
//                 }
//             };
//         }
//     };
// }

// pub fn PhysicalHeap(comptime architecture: lib.Target.Cpu.Arch) type {
//     const PA = addresses.PhysicalAddress(architecture, .global);
//     const PMR = addresses.PhysicalMemoryRegion(architecture, .global);
//
//     return extern struct {
//         allocator: Allocator = .{
//             .callback_allocate = callback_allocate,
//         },
//         regions: [6]addresses.PhysicalMemoryRegion(architecture, .global) = lib.zeroes([6]PMR),
//         page_allocator: *Allocator,
//
//         const Region = extern struct {
//             descriptor: PMR,
//         };
//
//         pub fn callback_allocate(allocator: *Allocator, size: u64, alignment: u64) Allocator.Allocate.Error!Allocator.Allocate.Result {
//             _ = alignment;
//             const physical_heap = @fieldParentPtr(PhysicalHeap(architecture), "allocator", allocator);
//             for (physical_heap.regions) |*region| {
//                 if (region.size > size) {
//                     const result = .{
//                         .address = region.address.value(),
//                         .size = size,
//                     };
//                     region.size -= size;
//                     region.address.addOffset(size);
//                     return result;
//                 }
//             }
//
//             const size_to_page_allocate = lib.alignForwardGeneric(u64, size, lib.arch.valid_page_sizes[0]);
//             for (physical_heap.regions) |*region| {
//                 if (region.size == 0) {
//                     const allocated_region = try physical_heap.page_allocator.allocateBytes(size_to_page_allocate, lib.arch.valid_page_sizes[0]);
//                     region.* = .{
//                         .address = PA.new(allocated_region.address),
//                         .size = allocated_region.size,
//                     };
//                     const result = .{
//                         .address = region.address.value(),
//                         .size = size,
//                     };
//                     region.address.addOffset(size);
//                     region.size -= size;
//                     return result;
//                 }
//             }
//
//             @panic("todo: allocate");
//         }
//     };
// }

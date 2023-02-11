pub const BIOS = @import("bootloader/bios.zig");
pub const UEFI = @import("bootloader/uefi.zig");
pub const limine = @import("bootloader/limine/limine.zig");

const lib = @import("lib.zig");
const assert = lib.assert;
const Allocator = lib.Allocator;
pub const Protocol = lib.Bootloader.Protocol;

const privileged = @import("privileged.zig");
const AddressInterface = privileged.Address.Interface(u64);
const PhysicalAddress = AddressInterface.PhysicalAddress;
const VirtualAddress = AddressInterface.VirtualAddress;
const PhysicalMemoryRegion = AddressInterface.PhysicalMemoryRegion;
const VirtualMemoryRegion = AddressInterface.VirtualMemoryRegion;

pub const Version = extern struct {
    patch: u8,
    minor: u16,
    major: u8,
};

pub const CompactDate = packed struct(u16) {
    year: u7,
    month: u4,
    day: u5,
};

pub const Information = extern struct {
    entry_point: u64,
    extra_size: u32,
    struct_size: u32,
    total_size: u32,
    version: Version,
    protocol: lib.Bootloader.Protocol,
    bootloader: lib.Bootloader,
    page_allocator: Allocator = .{
        .callbacks = .{
            .allocate = pageAllocate,
        },
    },
    heap: Heap,
    cpu_driver_mappings: CPUDriverMappings,
    framebuffer: Framebuffer,
    cpu: CPU.Information = .{},
    architecture: switch (lib.cpu.arch) {
        .x86, .x86_64 => extern struct {
            rsdp_address: u64,
        },
        else => @compileError("Architecture not supported"),
    },
    slices: [Slice.count]Slice,

    pub const Slice = extern struct {
        offset: u32 = 0,
        size: u32 = 0,
        len: u32 = 0,

        pub const Name = enum(u8) {
            cpu_driver_stack = 0,
            memory_map_entries = 1,
            page_counters = 2,
            external_bootloader_page_counters = 3,
            cpus = 4,
        };

        pub const count = lib.enumCount(Name);

        pub const TypeMap = blk: {
            var arr: [Slice.count]type = undefined;
            arr[@enumToInt(Slice.Name.cpu_driver_stack)] = u8;
            arr[@enumToInt(Slice.Name.memory_map_entries)] = MemoryMapEntry;
            arr[@enumToInt(Slice.Name.page_counters)] = u32;
            arr[@enumToInt(Slice.Name.external_bootloader_page_counters)] = u32;
            arr[@enumToInt(Slice.Name.cpus)] = CPU;
            break :blk arr;
        };
    };

    // TODO:
    const PA = PhysicalAddress(.global);
    const PMR = PhysicalMemoryRegion(.global);

    const Heap = extern struct {
        allocator: Allocator = .{
            .callbacks = .{
                .allocate = heapAllocate,
            },
        },
        regions: [6]PMR = lib.zeroes([6]PMR),
    };

    pub const Framebuffer = extern struct {
        address: u64,
        pitch: u32,
        width: u32,
        height: u32,
        bpp: u16,
        red_mask: ColorMask,
        green_mask: ColorMask,
        blue_mask: ColorMask,
        memory_model: u8,
        reserved: u8 = 0,

        pub const ColorMask = extern struct {
            size: u8 = 0,
            shift: u8 = 0,
        };

        pub const VideoMode = extern struct {
            foo: u32 = 0,
        };
    };

    pub const CPU = extern struct {
        foo: u64 = 0,

        pub const Information = extern struct {
            foo: u64 = 0,
        };
    };

    pub inline fn getSlice(information: *Information, comptime offset_name: Slice.Name) []Slice.TypeMap[@enumToInt(offset_name)] {
        const offset = information.slices[@enumToInt(offset_name)];
        const region = VirtualMemoryRegion(.local){
            .address = VirtualAddress(.local).new(@ptrToInt(information) + offset.offset),
            .size = offset.size,
        };
        return region.access(Slice.TypeMap[@enumToInt(offset_name)]);
    }

    pub fn getMemoryMapEntries(information: *Information) []MemoryMapEntry {
        return information.getSlice(.memory_map_entries);
    }

    pub fn getPageCounters(information: *Information) []u32 {
        return information.getSlice(.page_counters);
    }

    pub fn getExternalBootloaderPageCounters(information: *Information) []u32 {
        return information.getSlice(.external_bootloader_page_counters);
    }

    pub fn getStructAlignedSizeOnCurrentArchitecture() u32 {
        return lib.alignForwardGeneric(u32, @sizeOf(Information), lib.arch.valid_page_sizes[0]);
    }

    pub fn isSizeRight(information: *const Information) bool {
        const struct_size = @sizeOf(Information);
        const aligned_struct_size = comptime getStructAlignedSizeOnCurrentArchitecture();

        var extra_size: u32 = 0;
        inline for (Information.Slice.TypeMap) |T, index| {
            const slice = information.slices[index];
            const slice_size = @sizeOf(T) * slice.len;
            if (slice_size != slice.size) return false;
            extra_size += slice_size;
        }

        const aligned_extra_size = lib.alignForward(extra_size, lib.arch.valid_page_sizes[0]);
        const total_size = aligned_struct_size + aligned_extra_size;
        if (struct_size != information.struct_size) return false;
        if (extra_size != information.extra_size) return false;
        if (total_size != information.total_size) return false;

        return true;
    }

    pub fn pageAllocate(allocator: *Allocator, size: u64, alignment: u64) Allocator.Allocate.Error!Allocator.Allocate.Result {
        const bootloader_information = @fieldParentPtr(Information, "page_allocator", allocator);

        if (size & lib.arch.page_mask(lib.arch.valid_page_sizes[0]) != 0) return Allocator.Allocate.Error.OutOfMemory;
        if (alignment & lib.arch.page_mask(lib.arch.valid_page_sizes[0]) != 0) return Allocator.Allocate.Error.OutOfMemory;
        const four_kb_pages = @intCast(u32, @divExact(size, lib.arch.valid_page_sizes[0]));

        const entries = bootloader_information.getMemoryMapEntries();
        const page_counters = bootloader_information.getPageCounters();
        const external_bootloader_page_counters = bootloader_information.getExternalBootloaderPageCounters();

        for (entries) |entry, entry_index| {
            if (external_bootloader_page_counters.len == 0 or external_bootloader_page_counters[entry_index] == 0) {
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

const lib = @import("../../../lib.zig");
const log = lib.log;
const privileged = @import("../../../privileged.zig");
const ACPI = privileged.ACPI;
const MemoryMap = privileged.MemoryMap;
const MemoryManager = privileged.MemoryManager;
const PhysicalHeap = privileged.PhyicalHeap;
const writer = privileged.writer;
pub const panic = privileged.zigPanic;

const x86_64 = privileged.arch.x86_64;
const GDT = x86_64.GDT;
const PhysicalAddress = x86_64.PhysicalAddress;
const VirtualAddress = x86_64.VirtualAddress;
const PhysicalMemoryRegion = x86_64.PhysicalMemoryRegion;
const VirtualMemoryRegion = x86_64.VirtualMemoryRegion;
const VirtualAddressSpace = x86_64.VirtualAddressSpace;

const bootloader = @import("../../../bootloader.zig");
const BIOS = bootloader.BIOS;

extern const loader_start: u8;
extern const loader_end: u8;

var files: [16]struct { path: []const u8, content: []const u8 } = undefined;
var file_count: u8 = 0;

var gdt = GDT.Table{
    .tss_descriptor = undefined,
};

pub fn initializeBootloaderInformation(stack_size: usize) !*bootloader.Information {
    var iterator = BIOS.E820Iterator{};
    var vbe_info: BIOS.VBE.Information = undefined;

    const edid_info = try BIOS.VBE.getEDIDInfo();
    const edid_width = edid_info.getWidth();
    const edid_height = edid_info.getHeight();
    const edid_bpp = 32;
    const preferred_resolution = if (edid_width != 0 and edid_height != 0) .{ .x = edid_width, .y = edid_height } else @panic("No EDID");
    _ = preferred_resolution;
    try BIOS.VBE.getControllerInformation(&vbe_info);

    if (!lib.equal(u8, &vbe_info.signature, "VESA")) {
        return BIOS.VBE.Error.bad_signature;
    }

    if (vbe_info.version_major != 3 and vbe_info.version_minor != 0) {
        return BIOS.VBE.Error.unsupported_version;
    }

    const edid_video_mode = vbe_info.getVideoMode(BIOS.VBE.Mode.defaultIsValid, edid_width, edid_height, edid_bpp) orelse @panic("No video mode");
    const framebuffer_region = PhysicalMemoryRegion(.global).new(PhysicalAddress(.global).new(edid_video_mode.framebuffer_address), edid_video_mode.linear_bytes_per_scanline * edid_video_mode.resolution_y);

    const rsdp_address = BIOS.findRSDP() orelse @panic("Can't find RSDP");
    const rsdp = @intToPtr(*ACPI.RSDP.Descriptor1, rsdp_address);
    const madt_header = rsdp.findTable(.APIC) orelse @panic("Can't find MADT");
    const madt = @fieldParentPtr(ACPI.MADT, "header", madt_header);
    const cpu_count = madt.getCPUCount();
    const memory_map_entry_count = BIOS.getMemoryMapEntryCount();

    const aligned_struct_size = bootloader.Information.getStructAlignedSizeOnCurrentArchitecture();

    var extra_size: u32 = 0;
    const length_size_tuples = blk: {
        var arr = [1]struct { length: u32, size: u32 }{.{ .length = 0, .size = 0 }} ** bootloader.Information.Slice.count;
        arr[@enumToInt(bootloader.Information.Slice.Name.memory_map_entries)].length = memory_map_entry_count;
        arr[@enumToInt(bootloader.Information.Slice.Name.page_counters)].length = memory_map_entry_count;
        arr[@enumToInt(bootloader.Information.Slice.Name.external_bootloader_page_counters)].length = 0;
        arr[@enumToInt(bootloader.Information.Slice.Name.cpu_driver_stack)].length = stack_size;
        arr[@enumToInt(bootloader.Information.Slice.Name.cpus)].length = cpu_count;

        inline for (bootloader.Information.Slice.TypeMap) |T, index| {
            const size = arr[index].length * @sizeOf(T);
            extra_size += size;
            arr[index].size = size;
        }
        break :blk arr;
    };

    const aligned_extra_size = lib.alignForward(extra_size, lib.arch.valid_page_sizes[0]);
    const total_size = aligned_struct_size + aligned_extra_size;

    while (iterator.next()) |entry| {
        if (entry.descriptor.isUsable() and entry.descriptor.region.size > total_size and !entry.descriptor.region.overlaps(framebuffer_region)) {
            const bootloader_information_region = entry.descriptor.region.takeSlice(@sizeOf(bootloader.Information));
            const result = bootloader_information_region.address.toIdentityMappedVirtualAddress().access(*bootloader.Information);

            result.* = .{
                .protocol = .bios,
                .bootloader = .rise,
                .version = .{ .major = 0, .minor = 1, .patch = 0 },
                .struct_size = @sizeOf(bootloader.Information),
                .extra_size = extra_size,
                .total_size = total_size,
                .entry_point = 0,
                .heap = .{},
                .framebuffer = .{
                    .address = framebuffer_region.address.value(),
                    .pitch = edid_video_mode.linear_bytes_per_scanline,
                    .width = edid_video_mode.resolution_x,
                    .height = edid_video_mode.resolution_y,
                    .bpp = edid_video_mode.bpp,
                    .red_mask = .{
                        .shift = edid_video_mode.linear_red_mask_shift,
                        .size = edid_video_mode.linear_red_mask_size,
                    },
                    .green_mask = .{
                        .shift = edid_video_mode.linear_green_mask_shift,
                        .size = edid_video_mode.linear_green_mask_size,
                    },
                    .blue_mask = .{
                        .shift = edid_video_mode.linear_blue_mask_shift,
                        .size = edid_video_mode.linear_blue_mask_size,
                    },
                    // TODO:
                    .memory_model = 0,
                },
                .cpu_driver_mappings = .{},
                .slices = .{},
                .architecture = .{
                    .rsdp_address = rsdp_address,
                },
            };

            var allocated_size: usize = 0;

            inline for (result.slices) |*slice, index| {
                const tuple = length_size_tuples[index];
                const length = tuple.length;
                const size = tuple.size;
                slice.* = .{
                    .offset = allocated_size + comptime bootloader.Information.getStructAlignedSizeOnCurrentArchitecture(),
                    .len = length,
                    .size = size,
                };

                if (allocated_size + size > result.extra_size) @panic("size exceeded");

                allocated_size += size;
            }

            if (allocated_size != extra_size) @panic("Extra allocation size must match bootloader allocated extra size");

            const page_counters = result.getSlice(.page_counters);
            for (page_counters) |*page_counter| {
                page_counter.* = 0;
            }

            page_counters[entry.index] = total_size >> lib.arch.page_shifter(lib.arch.valid_page_sizes[0]);

            const memory_map_entries = result.getSlice(.memory_map_entries);
            BIOS.fetchMemoryEntries(memory_map_entries);

            return result;
        }
    }

    return lib.Allocator.Allocate.Error.OutOfMemory;
}

export fn entryPoint() callconv(.C) noreturn {
    BIOS.A20Enable() catch @panic("can't enable a20");
    lib.log.debug("Loader start: 0x{x}. Loader end: 0x{x}", .{ @ptrToInt(&loader_start), @ptrToInt(&loader_end) });
    writer.writeAll("[STAGE 1] Initializing\n") catch unreachable;

    const bootloader_information = initializeBootloaderInformation(privileged.default_stack_size) catch |err| privileged.panic("Can't get bootloader_information: {}", .{err});
    const page_allocator = &bootloader_information.page_allocator;
    const allocator = &bootloader_information.heap.allocator;

    var bios_disk = BIOS.Disk{
        .disk = .{
            // TODO:
            .disk_size = 64 * 1024 * 1024,
            .sector_size = 0x200,
            .callbacks = .{
                .read = BIOS.Disk.read,
                .write = BIOS.Disk.write,
            },
            .type = .bios,
        },
    };

    const gpt_cache = lib.PartitionTable.GPT.Partition.Cache.fromPartitionIndex(&bios_disk.disk, 0, allocator) catch @panic("can't load gpt cache");
    const fat_cache = lib.Filesystem.FAT32.Cache.fromGPTPartitionCache(allocator, gpt_cache) catch @panic("can't load fat cache");
    const rise_files_file = fat_cache.readFile(allocator, "/files") catch @panic("cant load json from disk");
    var file_parser = lib.FileParser.init(rise_files_file);
    const cpu_driver_name = blk: {
        var maybe_cpu_driver_name: ?[]const u8 = null;
        while (file_parser.next() catch @panic("parser error")) |file_descriptor| {
            if (file_count == files.len) @panic("max files");
            if (file_descriptor.type == .cpu_driver) {
                if (maybe_cpu_driver_name != null) @panic("Two cpu drivers");
                maybe_cpu_driver_name = file_descriptor.guest;
            }

            const file_content = fat_cache.readFile(allocator, file_descriptor.guest) catch @panic("cant read file");
            files[file_count] = .{
                .path = file_descriptor.guest,
                .content = file_content,
            };
            file_count += 1;
        }

        break :blk maybe_cpu_driver_name orelse @panic("No CPU driver specified in the configuration");
    };

    var kernel_address_space = blk: {
        const allocation_result = page_allocator.allocateBytes(privileged.arch.x86_64.paging.needed_physical_memory_for_bootstrapping_kernel_address_space, lib.arch.valid_page_sizes[0]) catch @panic("Unable to get physical memory to bootstrap kernel address space");
        const kernel_address_space_physical_region = PhysicalMemoryRegion(.local){
            .address = PhysicalAddress(.local).new(allocation_result.address),
            .size = VirtualAddressSpace.needed_physical_memory_for_bootstrapping_kernel_address_space,
        };
        const result = VirtualAddressSpace.kernelBSP(kernel_address_space_physical_region);
        break :blk result;
    };

    const entries = bootloader_information.getMemoryMapEntries();
    for (entries) |entry| {
        if (entry.type == .usable) {
            VirtualAddressSpace.paging.bootstrap_map(&kernel_address_space, .global, entry.region.address, entry.region.address.toIdentityMappedVirtualAddress(), lib.alignForwardGeneric(u64, entry.region.size, lib.arch.valid_page_sizes[0]), .{ .write = true, .execute = true }, page_allocator) catch @panic("Mapping of memory map entry failed");
        }
    }

    const loader_physical_start = PhysicalAddress(.global).new(lib.alignBackward(@ptrToInt(&loader_start), lib.arch.valid_page_sizes[0]));
    const loader_size = lib.alignForwardGeneric(u64, @ptrToInt(&loader_end) - @ptrToInt(&loader_start) + @ptrToInt(&loader_start) - loader_physical_start.value(), lib.arch.valid_page_sizes[0]);
    VirtualAddressSpace.paging.bootstrap_map(&kernel_address_space, .global, loader_physical_start, loader_physical_start.toIdentityMappedVirtualAddress(), lib.alignForwardGeneric(u64, loader_size, lib.arch.valid_page_sizes[0]), .{ .write = true, .execute = true }, page_allocator) catch |err| {
        log.debug("Error: {}", .{err});
        @panic("Mapping of BIOS loader failed");
    };
    const framebuffer_physical_address = PhysicalAddress(.global).new(bootloader_information.framebuffer.address);
    VirtualAddressSpace.paging.bootstrap_map(&kernel_address_space, .global, framebuffer_physical_address, framebuffer_physical_address.toIdentityMappedVirtualAddress(), lib.alignForwardGeneric(u64, bootloader_information.framebuffer.pitch * bootloader_information.framebuffer.height, lib.arch.valid_page_sizes[0]), .{ .write = true, .execute = false }, page_allocator) catch @panic("can't map framebuffer");

    // Map more than necessary
    const loader_stack = PhysicalAddress(.global).new(0xe000);
    const loader_stack_size = 0x2000;
    VirtualAddressSpace.paging.bootstrap_map(&kernel_address_space, .global, loader_stack, loader_stack.toIdentityMappedVirtualAddress(), loader_stack_size, .{ .write = true, .execute = false }, page_allocator) catch @panic("Mapping of loader stack failed");

    for (files) |file| {
        if (lib.equal(u8, file.path, cpu_driver_name)) {
            var parser = lib.ELF(64).Parser.init(file.content) catch @panic("Can't parser ELF");

            const program_headers = parser.getProgramHeaders();
            for (program_headers) |*ph| {
                switch (ph.type) {
                    .load => {
                        if (ph.size_in_memory == 0) continue;

                        if (!ph.flags.readable) {
                            @panic("ELF program segment is marked as non-readable");
                        }

                        if (ph.size_in_file != ph.size_in_memory) {
                            @panic("ELF program segment file size is smaller than memory size");
                        }

                        const aligned_size = lib.alignForwardGeneric(u64, ph.size_in_memory, lib.arch.valid_page_sizes[0]);
                        const physical_allocation = page_allocator.allocateBytes(aligned_size, lib.arch.valid_page_sizes[0]) catch @panic("WTDASD");
                        const physical_address = PhysicalAddress(.local).new(physical_allocation.address);
                        const virtual_address = VirtualAddress(.local).new(ph.virtual_address);

                        switch (ph.flags.executable) {
                            true => switch (ph.flags.writable) {
                                true => @panic("Text section is not supposed to be writable"),
                                false => bootloader_information.cpu_driver_mappings.text.virtual = virtual_address,
                            },
                            false => switch (ph.flags.writable) {
                                true => bootloader_information.cpu_driver_mappings.data.virtual = virtual_address,
                                false => bootloader_information.cpu_driver_mappings.rodata.virtual = virtual_address,
                            },
                        }

                        VirtualAddressSpace.paging.bootstrap_map(&kernel_address_space, .local, physical_address, virtual_address, aligned_size, .{ .write = ph.flags.writable, .execute = ph.flags.executable }, page_allocator) catch {
                            @panic("Mapping failed");
                        };

                        const dst_slice = physical_address.toIdentityMappedVirtualAddress().access([*]u8)[0..lib.safeArchitectureCast(ph.size_in_memory)];
                        const src_slice = file.content[lib.safeArchitectureCast(ph.offset)..][0..lib.safeArchitectureCast(ph.size_in_file)];
                        if (!(dst_slice.len >= src_slice.len)) {
                            @panic("WTFFFFFFF");
                        }

                        lib.copy(u8, dst_slice, src_slice);
                    },
                    else => {
                        //log.warn("Unhandled PH {s}", .{@tagName(ph.type)});
                    },
                }
            }

            // Map this struct

            const bootloader_information_physical_address = PhysicalAddress(.local).new(@ptrToInt(bootloader_information));
            const bootloader_information_virtual_address = bootloader_information_physical_address.toHigherHalfVirtualAddress();
            VirtualAddressSpace.paging.bootstrap_map(&kernel_address_space, .local, bootloader_information_physical_address, bootloader_information_virtual_address, bootloader_information.total_size, .{ .write = true, .execute = false }, page_allocator) catch @panic("Mapping failed");

            comptime {
                lib.assert(@offsetOf(GDT.Table, "code_64") == 0x08);
            }

            bootloader_information.entry_point = parser.getEntryPoint();

            // Enable PAE
            {
                var cr4 = asm volatile (
                    \\mov %%cr4, %[cr4]
                    : [cr4] "=r" (-> u32),
                );
                cr4 |= (1 << 5);
                asm volatile (
                    \\mov %[cr4], %%cr4 
                    :
                    : [cr4] "r" (cr4),
                );
            }

            kernel_address_space.makeCurrent();

            // Enable long mode
            {
                var efer = privileged.arch.x86_64.registers.IA32_EFER.read();
                efer.LME = true;
                efer.NXE = true;
                efer.SCE = true;
                efer.write();
            }

            // Enable paging
            {
                var cr0 = asm volatile (
                    \\mov %%cr0, %[cr0]
                    : [cr0] "=r" (-> u32),
                );
                cr0 |= (1 << 31);
                asm volatile (
                    \\mov %[cr0], %%cr0 
                    :
                    : [cr0] "r" (cr0),
                );
            }

            gdt.setup(0, false);

            writer.writeAll("[STAGE 1] Trying to jump to CPU driver...\n") catch unreachable;

            if (bootloader_information.entry_point != 0) {
                const entry_point_offset = @offsetOf(bootloader.Information, "entry_point");
                const stack_offset = @offsetOf(bootloader.Information, "slices") + (@as(u32, @enumToInt(bootloader.Information.Slice.Name.cpu_driver_stack)) * @sizeOf(bootloader.Information.Slice));
                trampoline(bootloader_information_virtual_address.value(), entry_point_offset, stack_offset);
            }
        }
    }

    @panic("loader not found");
}

// TODO: stop this weird stack manipulation and actually learn x86 calling convention
pub extern fn trampoline(bootloader_information: u64, entry_point_offset: u64, stack_offset: u64) noreturn;
comptime {
    const offset_offset = @offsetOf(bootloader.Information.Slice, "offset");
    const size_offset = @offsetOf(bootloader.Information.Slice, "size");
    lib.assert(offset_offset == 0);
    lib.assert(size_offset == offset_offset + @sizeOf(u32));

    asm (
        \\.global trampoline
        \\trampoline:
        \\push %eax
        \\jmp $0x8, $bits64
        \\bits64:
        // When working with registers here without REX.W 0x48 prefix, we are actually working with 64-bit ones
        \\pop %eax 
        // RDI: bootloader_information
        \\pop %edi 
        \\pop %eax
        // RAX: entry_point
        \\.byte 0x48
        \\mov (%edi, %eax, 1), %eax
        // RSI: stack mapping offset
        \\pop %esi
        \\.byte 0x48
        \\add %edi, %esi
        \\mov (%esi), %esp
        \\add 0x4(%esi), %esp
        \\.byte 0x48
        \\add %esi, %esp
        \\xor %ebp, %ebp
        // jmp rax
        \\.byte 0xff
        \\.byte 0xe0
    );
}

pub const std_options = struct {
    pub const log_level = lib.std.log.Level.debug;

    pub fn logFn(comptime level: lib.std.log.Level, comptime scope: @TypeOf(.EnumLiteral), comptime format: []const u8, args: anytype) void {
        _ = level;
        writer.writeByte('[') catch unreachable;
        writer.writeAll(@tagName(scope)) catch unreachable;
        writer.writeAll("] ") catch unreachable;
        lib.format(writer, format, args) catch unreachable;
        writer.writeByte('\n') catch unreachable;
    }
};

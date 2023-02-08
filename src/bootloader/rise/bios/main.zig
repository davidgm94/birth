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

export fn entryPoint() callconv(.C) noreturn {
    BIOS.A20Enable() catch @panic("can't enable a20");
    writer.writeAll("[STAGE 1] Initializing\n") catch unreachable;

    const rsdp_address = BIOS.findRSDP() orelse @panic("Can't find RSDP");
    const rsdp = @intToPtr(*ACPI.RSDP.Descriptor1, rsdp_address);
    const madt_header = rsdp.findTable(.APIC) orelse @panic("Can't find MADT");
    const madt = @fieldParentPtr(ACPI.MADT, "header", madt_header);
    const cpu_count = madt.getCPUCount();

    const memory_map_entry_count = BIOS.getMemoryMapEntryCount();
    log.debug("CPU count: {}", .{cpu_count});

    const bootloader_information = bootloader.Information.fromBIOS(rsdp_address, memory_map_entry_count, privileged.default_stack_size) catch @panic("Can't get bootloader information");
    const page_allocator = &bootloader_information.page.allocator;
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
    while (file_parser.next() catch @panic("parser error")) |file_descriptor| {
        if (file_count == files.len) @panic("max files");
        const file_content = fat_cache.readFile(allocator, file_descriptor.guest) catch @panic("cant read file");
        files[file_count] = .{
            .path = file_descriptor.guest,
            .content = file_content,
        };
        file_count += 1;
    }

    var kernel_address_space = blk: {
        const allocation_result = page_allocator.allocateBytes(privileged.arch.x86_64.paging.needed_physical_memory_for_bootstrapping_kernel_address_space, lib.arch.valid_page_sizes[0]) catch @panic("Unable to get physical memory to bootstrap kernel address space");
        const kernel_address_space_physical_region = PhysicalMemoryRegion(.local){
            .address = PhysicalAddress(.local).new(allocation_result.address),
            .size = VirtualAddressSpace.needed_physical_memory_for_bootstrapping_kernel_address_space,
        };
        const result = VirtualAddressSpace.kernelBSP(kernel_address_space_physical_region);
        break :blk result;
    };

    const entries = bootloader_information.memory_map.getNativeEntries(.bios);
    for (entries) |entry| {
        if (entry.type == .usable) {
            VirtualAddressSpace.paging.bootstrap_map(&kernel_address_space, .global, entry.region.address, entry.region.address.toIdentityMappedVirtualAddress(), lib.alignForwardGeneric(u64, entry.region.size, lib.arch.valid_page_sizes[0]), .{ .write = true, .execute = true }, page_allocator) catch @panic("mapping failed");
        }
    }

    if (true) @panic("TODO: BIOS main");

    for (files) |file| {
        if (lib.equal(u8, file.path, "/CPUDRIV")) {
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

            bootloader_information.cpu_driver_mappings.stack.virtual = bootloader_information.cpu_driver_mappings.text.virtual.negative_offset(bootloader_information.cpu_driver_mappings.stack.size);
            log.debug("Text VA: 0x{x}. Stack VA: 0x{x}", .{ bootloader_information.cpu_driver_mappings.text.virtual.value(), bootloader_information.cpu_driver_mappings.stack.virtual.value() });
            VirtualAddressSpace.paging.bootstrap_map(&kernel_address_space, .local, bootloader_information.cpu_driver_mappings.stack.physical, bootloader_information.cpu_driver_mappings.stack.virtual, bootloader_information.cpu_driver_mappings.stack.size, .{ .write = true, .execute = false }, page_allocator) catch {
                @panic("Mapping failed");
            };

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
                const stack_offset = @offsetOf(bootloader.Information, "cpu_driver_mappings") + @offsetOf(bootloader.CPUDriverMappings, "stack");
                log.debug("BI: 0x{x}. Entry point offset: 0x{x}. Stack offset: 0x{x}. Stack: {}", .{ @ptrToInt(bootloader_information), entry_point_offset, stack_offset, bootloader_information.cpu_driver_mappings.stack });
                trampoline(@ptrToInt(bootloader_information), entry_point_offset, stack_offset);
            }
        }
    }

    @panic("loader not found");
}

// TODO: stop this weird stack manipulation and actually learn x86 calling convention
pub extern fn trampoline(bootloader_information: u64, entry_point_offset: u64, stack_offset: u64) noreturn;
comptime {
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
        \\.byte 0x48
        \\add $0x8, %esi
        \\.byte 0x48
        \\mov (%esi), %ecx
        \\.byte 0x48
        \\addl 0x8(%esi), %ecx
        \\.byte 0x48
        \\mov %ecx, %esp
        \\.byte 0x48
        \\xor %ebp, %ebp
        // jmp rax
        \\.byte 0xff
        \\.byte 0xe0
    );
}

pub const std_options = struct {
    pub const log_level = lib.std.log.Level.debug;

    pub fn logFn(comptime level: lib.std.log.Level, comptime scope: @TypeOf(.EnumLiteral), comptime format: []const u8, args: anytype) void {
        _ = scope;
        _ = level;
        lib.format(writer, format, args) catch unreachable;
        writer.writeByte('\n') catch unreachable;
    }
};

const lib = @import("lib");
const log = lib.log;
const privileged = @import("privileged");
const MemoryMap = privileged.MemoryMap;
const MemoryManager = privileged.MemoryManager;
const PhysicalHeap = privileged.PhysicalHeap;

const x86_64 = privileged.arch.x86_64;
const GDT = x86_64.GDT;
const PhysicalAddress = x86_64.PhysicalAddress;
const VirtualAddress = x86_64.VirtualAddress;
const PhysicalMemoryRegion = x86_64.PhysicalMemoryRegion;
const VirtualMemoryRegion = x86_64.VirtualMemoryRegion;
const VirtualAddressSpace = x86_64.VirtualAddressSpace;

const bootloader = @import("bootloader");
const BIOS = bootloader.BIOS;

export fn loop() noreturn {
    asm volatile (
        \\cli
        \\hlt
    );

    while (true) {}
}

extern const loader_start: u8;
extern const loader_end: u8;

pub const writer = privileged.E9Writer{ .context = {} };

pub fn panic(message: []const u8, stack_trace: ?*lib.StackTrace, ret_addr: ?usize) noreturn {
    _ = stack_trace;
    _ = ret_addr;

    while (true) {
        asm volatile ("cli");
        writer.writeAll("PANIC: ") catch unreachable;
        writer.writeAll(message) catch unreachable;
        writer.writeByte('\n') catch unreachable;
        asm volatile ("hlt");
    }
}

var files: [16]struct { path: []const u8, content: []const u8 } = undefined;
var file_count: u8 = 0;

var gdt = GDT.Table{
    .tss_descriptor = undefined,
};

export fn entryPoint() callconv(.C) noreturn {
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

    writer.writeAll("[STAGE 1] Initializing\n") catch unreachable;
    BIOS.A20Enable() catch @panic("can't enable a20");

    const bootloader_information = bootloader.Information.fromBIOS() catch @panic("Can't get bootloader information");
    const page_allocator = &bootloader_information.page.allocator;
    const allocator = &bootloader_information.heap.allocator;

    if (bios_disk.disk.sector_size != 0x200) {
        @panic("Wtf");
    }

    const gpt_cache = lib.PartitionTable.GPT.Partition.Cache.fromPartitionIndex(&bios_disk.disk, 0, allocator) catch @panic("can't load gpt cache");
    const fat_cache = lib.Filesystem.FAT32.Cache.fromGPTPartitionCache(allocator, gpt_cache) catch @panic("can't load fat cache");
    const rise_files_file = fat_cache.read_file(allocator, "/files") catch @panic("cant load json from disk");
    var file_parser = lib.FileParser.init(rise_files_file);
    while (file_parser.next() catch @panic("parser error")) |file_descriptor| {
        if (file_count == files.len) @panic("max files");
        const file_content = fat_cache.read_file(allocator, file_descriptor.guest) catch @panic("cant read file");
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

    for (files) |file| {
        if (lib.equal(u8, file.path, "/CPUDRV")) {
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

            comptime {
                lib.assert(@offsetOf(GDT.Table, "code_64") == 0x08);
            }

            log.debug("Size of information: 0x{x}", .{@sizeOf(bootloader.Information)});

            const stack_allocation = page_allocator.allocateBytes(0x4000, 0x1000) catch @panic("Stack allocation");
            const stack_top = stack_allocation.address + stack_allocation.size;

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

            bootloader.Information.printBootloaderInfo();

            writer.writeAll("[STAGE 1] Trying to jump to CPU driver...\n") catch unreachable;

            // Hardcode the trampoline here since this is a 32-bit executable and assembling 64-bit code is not allowed
            asm volatile (
                \\mov %[entry_point_low], %%edi
                \\mov %[entry_point_high], %%esi
                \\mov %[bootloader_information], %%edx
                \\mov %[stack_top], %%ecx
                \\jmp $0x8, $bits64
                \\bits64:
                //0:  48 31 c0                xor    rax,rax
                \\.byte 0x48
                \\.byte 0x31
                \\.byte 0xc0
                //3:  89 f0                   mov    eax,esi
                \\.byte 0x89
                \\.byte 0xf0
                //5:  48 c1 e0 20             shl    rax,0x20
                \\.byte 0x48
                \\.byte 0xc1
                \\.byte 0xe0
                \\.byte 0x20
                //9:  48 09 f8                or     rax,rdi
                \\.byte 0x48
                \\.byte 0x09
                \\.byte 0xf8

                // 0:  48 89 d7                mov    rdi,rdx
                \\.byte 0x48
                \\.byte 0x89
                \\.byte 0xd7

                // 0:  48 31 ed                xor    rbp,rbp
                \\.byte 0x48
                \\.byte 0x31
                \\.byte 0xed

                // 3:  48 89 cc                mov    rsp,rcx
                \\.byte 0x48
                \\.byte 0x89
                \\.byte 0xcc

                //c:  ff e0                   jmp    rax
                \\.byte 0xff
                \\.byte 0xe0
                :
                : [entry_point_low] "{edi}" (@truncate(u32, parser.getEntryPoint())),
                  [entry_point_high] "{esi}" (@truncate(u32, parser.getEntryPoint() >> 32)),
                  [bootloader_information] "{edx}" (bootloader_information),
                  [stack_top] "{ecx}" (stack_top),
            );
        }
    }

    @panic("loader not found");
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

const common = @import("common");
const assert = common.assert;
const logger = common.log.scoped(.EntryPoint);

const privileged = @import("privileged");
const PhysicalAddress = privileged.PhysicalAddress;
const PhysicalMemoryRegion = privileged.PhysicalMemoryRegion;
const PhysicalAddressSpace = privileged.PhysicalAddressSpace;
const VirtualAddress = privileged.VirtualAddress;
const UEFI = privileged.UEFI;

const arch = @import("arch");
const CPU = arch.CPU;
const x86_64 = arch.x86_64;
const APIC = x86_64.APIC;
const IDT = x86_64.IDT;

const MemoryMap = struct {
    const Entry = struct {
        physical_address: PhysicalAddress,
        size: u64,
        native_attributes: u64,
        tag: Type,
        const Type = enum {
            usable,
            bootloader_reserved,
            bootloader_information,
            bootloader_reclaimable,
            firmware_reserved,
            firmware_reclaimable,
            reserved,
        };
    };
};

export fn kernel_entry_point(bootloader_information: *UEFI.BootloaderInformation) noreturn {
    logger.debug("Hello kernel", .{});
    IDT.setup();
    logger.debug("Loaded IDT", .{});

    // Claim some memory left from the bootloader

    var memory_map_iterator = bootloader_information.memory_map.iterator();
    var memory_map_conventional_entry_index: usize = 0;

    const entry_count = bootloader_information.counters.len;
    const physical_regions_allocation_size = @sizeOf(PhysicalAddressSpace.Region) * entry_count;

    const free_physical_regions = blk: {
        while (memory_map_iterator.next(bootloader_information.memory_map)) |entry| {
            if (entry.type == .ConventionalMemory) {
                const used_4k_page_count = bootloader_information.counters[memory_map_conventional_entry_index];
                const used_byte_count = used_4k_page_count << arch.page_shifter(arch.valid_page_sizes[0]);

                if (used_byte_count >= physical_regions_allocation_size) {
                    const physical_address = PhysicalAddress.new(entry.physical_start + used_byte_count);
                    bootloader_information.counters[memory_map_conventional_entry_index] += @intCast(u32, common.align_forward(physical_regions_allocation_size, arch.valid_page_sizes[0]) >> arch.page_shifter(arch.valid_page_sizes[0]));

                    const free_regions = physical_address.to_higher_half_virtual_address().access([*]PhysicalAddressSpace.Region)[0..entry_count];
                    memory_map_iterator.reset();
                    memory_map_conventional_entry_index = 0;

                    var maybe_previous: ?*PhysicalAddressSpace.Region = null;

                    while (memory_map_iterator.next(bootloader_information.memory_map)) |memory_map_entry| {
                        if (memory_map_entry.type == .ConventionalMemory) {
                            defer memory_map_conventional_entry_index += 1;

                            const entry_used_page_count = bootloader_information.counters[memory_map_conventional_entry_index];
                            const entry_used_byte_count = entry_used_page_count << arch.page_shifter(arch.valid_page_sizes[0]);

                            const entry_physical_address = PhysicalAddress.new(memory_map_entry.physical_start + entry_used_byte_count);
                            const entry_free_page_count = memory_map_entry.number_of_pages - entry_used_page_count;
                            const entry_free_byte_count = entry_free_page_count << arch.page_shifter(arch.valid_page_sizes[0]);

                            if (entry_free_byte_count != 0) {
                                const region = &free_regions[memory_map_conventional_entry_index];
                                region.* = .{
                                    .descriptor = .{
                                        .address = entry_physical_address,
                                        .size = entry_free_byte_count,
                                    },
                                    .previous = maybe_previous,
                                    .next = null,
                                };

                                if (maybe_previous) |previous| {
                                    previous.next = region;
                                }

                                maybe_previous = region;
                            }
                        }
                    }

                    break :blk free_regions;
                }

                memory_map_conventional_entry_index += 1;
            }
        }

        @panic("Unable to find a host entry for physical regions");
    };

    logger.debug("Finished processing memory map", .{});

    arch.startup.bsp_address_space = PhysicalAddressSpace{
        .free_list = .{
            .first = &free_physical_regions[0],
            .last = &free_physical_regions[free_physical_regions.len - 1],
            .count = free_physical_regions.len,
        },
    };

    const apic_base = APIC.init();

    // TODO: init RTC
    // TODO: setup timer properly
    if (common.config.timeslicing) {
        x86_64.APIC.calibrate_timer(apic_base);
    } else {
        logger.warn("Timeslicing not enabled", .{});
        @panic("todo implement no timeslicing");
    }

    logger.warn("TODO: Enable IPI", .{});
    arch.x86_64.Syscall.enable(@ptrToInt(&kernel_syscall_entry_point));

    // Enable no-execute protection
    {
        var efer = arch.x86_64.registers.IA32_EFER.read();
        efer.NXE = true;
        efer.write();
    }

    enable_fpu();

    logger.debug("Reached to the end", .{});
    CPU.stop();
}

fn enable_fpu() void {
    var cr0 = x86_64.registers.cr0.read();
    cr0.
}

pub fn log(comptime level: common.log.Level, comptime scope: @TypeOf(.EnumLiteral), comptime format: []const u8, args: anytype) void {
    const scope_prefix = if (scope == .default) ": " else "(" ++ @tagName(scope) ++ "): ";
    const prefix = "[" ++ @tagName(level) ++ "] " ++ scope_prefix;
    writer.writeAll(prefix) catch unreachable;

    writer.print(format, args) catch unreachable;
    writer.writeByte('\n') catch unreachable;
}

pub fn panic(message: []const u8, _: ?*common.StackTrace, _: ?usize) noreturn {
    asm volatile (
        \\cli
    );
    common.log.scoped(.PANIC).err("{s}", .{message});
    CPU.stop();
}

const Writer = common.Writer(void, error{}, e9_write);
const writer = Writer{ .context = {} };
fn e9_write(_: void, bytes: []const u8) error{}!usize {
    const bytes_left = asm volatile (
        \\cld
        \\rep outsb
        : [ret] "={rcx}" (-> usize),
        : [dest] "{dx}" (0xe9),
          [src] "{rsi}" (bytes.ptr),
          [len] "{rcx}" (bytes.len),
    );
    return bytes.len - bytes_left;
}

// TODO: implement syscall
pub export fn kernel_syscall_entry_point() callconv(.Naked) void {
    // This function only modifies RSP. The other registers are preserved in user space
    // This sets up the kernel stack before actually starting to run kernel code
    //asm volatile (
    //\\swapgs
    //// Save RFLAGS (R11), next instruction address after sysret (RCX) and user stack (RSP)
    //\\mov %%r11, %%r12
    //\\mov %%rcx, %%r13
    //\\mov %%rsp, %%r14
    //// Pass original RCX (4th argument)
    //\\mov %%rax, %%rcx
    //// Get kernel stack
    //\\mov %%gs:[0], %%r15
    //\\add %[offset], %%r15
    //\\mov (%%r15), %%r15
    //\\mov %%r15, %%rbp
    //// Use kernel stack
    //\\mov %%rbp, %%rsp
    //// Call the syscall handler
    //\\mov %[handler], %%rax
    //\\call *(%%rax)
    //// Restore RSP, R11 (RFLAGS) and RCX (RIP after sysret)
    //\\mov %%r14, %%rsp
    //\\mov %%r12, %%r11
    //\\mov %%r13, %%rcx
    //// Restore user GS
    //\\swapgs
    //// Go back to user mode
    //\\sysretq
    //:
    //: [offset] "i" (@intCast(u8, @offsetOf(Thread, "kernel_stack"))),
    //[handler] "i" (&Syscall.handler),
    //);

    @panic("reached unreachable: syscall handler");
}

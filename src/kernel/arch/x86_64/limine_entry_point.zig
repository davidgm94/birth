const common = @import("common");
const assert = common.assert;
const logger = common.log.scoped(.Limine);

const bootloader = @import("bootloader");
const Limine = bootloader.Limine;

const kernel = @import("kernel");

const RNU = @import("RNU");
const Heap = RNU.Heap;
const PhysicalAddress = RNU.PhysicalAddress;
const PhysicalAddressSpace = RNU.PhysicalAddressSpace;
const PhysicalMemoryRegion = RNU.PhysicalMemoryRegion;
const Scheduler = RNU.Scheduler;
const Spinlock = RNU.Spinlock;
const Thread = RNU.Thread;
const VirtualAddress = RNU.VirtualAddress;
const VirtualAddressSpace = RNU.VirtualAddressSpace;
const VirtualMemoryRegion = RNU.VirtualMemoryRegion;

const arch = @import("arch");
const Context = arch.Context;
const CPU = arch.CPU;
const TLS = arch.TLS;
const VAS = arch.VAS;

const x86_64 = arch.x86_64;

pub fn get_rsdp_physical_address() PhysicalAddress {
    switch (common.cpu.arch) {
        .x86_64 => {
            const response = bootloader_rsdp.response orelse @panic("RSDP response not present");
            if (response.address == 0) @panic("RSDP address is null");
            return PhysicalAddress.new(response.address - kernel.higher_half_direct_map.value);
        },
        else => @compileError("not supported"),
    }
}

pub export fn kernel_entry_point() noreturn {
    CPU.early_bsp_bootstrap();

    logger.debug("Hello kernel!", .{});

    if (bootloader_modules.response) |response| {
        logger.debug("Module count: {}", .{response.module_count});
    } else {
        logger.err("Module response not present", .{});
    }

    kernel.higher_half_direct_map = blk: {
        const response = bootloader_hhdm.response orelse @panic("HHDM response not present");
        if (response.offset == 0) @panic("No offset in HHDM response");
        break :blk VirtualAddress.new(response.offset);
    };
    logger.debug("HHDM: {}", .{kernel.higher_half_direct_map});

    const memory_map_response = bootloader_memory_map.response orelse @panic("Memory map response not present");
    const memory_map_entry_count = memory_map_response.entry_count;
    const memory_map_ptr_to_entry_ptr = memory_map_response.entries orelse @panic("Pointer to memory map entry pointer is null");
    const memory_map_entry_ptr = memory_map_ptr_to_entry_ptr.*;
    const memory_map_entries = memory_map_entry_ptr[0..memory_map_entry_count];
    {
        var usable_entry_count: u64 = 0;
        for (memory_map_entries) |entry| {
            usable_entry_count += @boolToInt(entry.type == .usable);
        }

        logger.debug("Usable entry count: {}", .{usable_entry_count});
        const usable_free_regions = kernel.bootstrap_allocator.allocator().alloc(PhysicalAddressSpace.FreePhysicalRegion, usable_entry_count) catch @panic("Unable to allocate usable free regions");
        var maybe_last: ?*PhysicalAddressSpace.FreePhysicalRegion = null;
        var usable_i: u64 = 0;

        for (memory_map_entries) |entry| {
            logger.debug("Physical memory region: {s}, (0x{x}, 0x{x})", .{ @tagName(entry.type), entry.address, entry.address + entry.size });
            switch (entry.type) {
                .usable => {
                    const region = &usable_free_regions[usable_i];
                    defer {
                        usable_i += 1;
                        if (maybe_last) |last| last.next = region;
                        maybe_last = region;
                    }
                    region.* = PhysicalAddressSpace.FreePhysicalRegion{
                        .descriptor = PhysicalMemoryRegion{
                            .address = PhysicalAddress.new(entry.address),
                            .size = entry.size,
                        },
                        .previous = maybe_last,
                    };
                },
                else => {},
            }
        }

        kernel.physical_address_space = PhysicalAddressSpace{
            .zero_free_list = .{
                .first = &usable_free_regions[0],
                .last = maybe_last,
                .count = usable_entry_count,
            },
        };
    }

    const kernel_address_response = bootloader_kernel_address.response orelse @panic("Kernel address response not present");
    // Init paging
    {

        // Kernel address space initialization
        VAS.init_kernel(kernel.virtual_address_space, &kernel.physical_address_space);
        logger.debug("New kernel address space CR3 0x{x}", .{@bitCast(u64, kernel.virtual_address_space.arch.cr3)});

        // Map the kernel and do some tests
        {
            logger.debug("Starting mapping kernel executable", .{});

            logger.debug("Kernel address. PA: 0x{x}. VA: 0x{x}", .{ kernel_address_response.physical_address, kernel_address_response.virtual_address });
            const kernel_base_physical_address = PhysicalAddress.new(kernel_address_response.physical_address);
            const kernel_base_virtual_address = VirtualAddress.new(kernel_address_response.virtual_address);
            // TODO: no execute

            for (memory_map_entries) |entry| {
                if (entry.type == .usable) {
                    const entry_physical_address = PhysicalAddress.new(entry.address);
                    logger.debug("Mapping usable region: ({}, {})", .{ entry_physical_address, entry_physical_address.offset(entry.size) });
                    VAS.bootstrap_map(entry_physical_address, entry_physical_address.to_higher_half_virtual_address(), @divExact(entry.size, x86_64.page_size), .{ .write = true });
                }
            }

            logger.debug("Ended mapping usable", .{});

            map_section("text", kernel_base_physical_address, kernel_base_virtual_address, .{ .execute = true });
            map_section("rodata", kernel_base_physical_address, kernel_base_virtual_address, .{ .execute = false });
            map_section("data", kernel_base_physical_address, kernel_base_virtual_address, .{ .write = true, .execute = false });

            for (memory_map_entries) |entry| {
                if (entry.type != .kernel_and_modules and entry.type != .usable and entry.type != .reserved) {
                    logger.debug("Mapping {s} region", .{@tagName(entry.type)});
                    const entry_physical_address = PhysicalAddress.new(entry.address);
                    VAS.bootstrap_map(entry_physical_address, entry_physical_address.to_higher_half_virtual_address(), @divExact(entry.size, x86_64.page_size), .{ .write = true });
                }
            }
        }

        // TODO: reclaimable, framebuffer, reserved, etc

        {
            kernel.virtual_address_space.make_current();
            kernel.process.virtual_address_space = kernel.virtual_address_space;
            //kernel.virtual_address_space.copy_to_new(&kernel.virtual_address_space);
        }

        kernel.memory_initialized = true;
        logger.debug("memory initialized", .{});

        {
            // Use the bootstrap allocator since we don't want any allocation happening here
            kernel.virtual_address_space.used_regions.ensureTotalCapacity(kernel.bootstrap_allocator.allocator(), 512) catch unreachable;
            kernel.virtual_address_space.free_regions.ensureTotalCapacity(kernel.bootstrap_allocator.allocator(), 512) catch unreachable;

            for (memory_map_entries) |entry| {
                const entry_physical_address = PhysicalAddress.new(entry.address);
                switch (entry.type) {
                    .usable, .bootloader_reclaimable, .framebuffer => {
                        _ = @divExact(entry.size, x86_64.page_size);
                        const entry_virtual_address = entry_physical_address.to_higher_half_virtual_address();

                        const region = VirtualAddressSpace.Region{
                            .address = entry_virtual_address,
                            .size = entry.size,
                            .flags = VirtualAddressSpace.Flags{
                                .write = true,
                            },
                        };

                        kernel.virtual_address_space.add_used_region(region) catch unreachable;
                    },
                    .kernel_and_modules => {
                        if (entry.address == kernel_address_response.physical_address) {
                            const region = VirtualAddressSpace.Region{
                                .address = VirtualAddress.new(kernel_address_response.virtual_address),
                                .size = entry.size,
                                // TODO: write proper flags
                                .flags = .{},
                            };
                            kernel.virtual_address_space.add_used_region(region) catch unreachable;
                        }
                    },
                    .reserved => {
                        // TODO:
                        // TODO: check if we should the same as above or not. For now, repeat it
                        //_ = @divExact(entry.size, x86_64.page_size);
                        //const entry_virtual_address = entry_physical_address.to_higher_half_virtual_address();

                        //const region = VirtualAddressSpace.Region{
                        //.address = entry_virtual_address,
                        //.size = entry.size,
                        //.flags = VirtualAddressSpace.Flags{
                        //.write = true,
                        //},
                        //};

                        //kernel.virtual_address_space.add_used_region(region) catch unreachable;
                    },
                    else => RNU.panic("ni: {}", .{entry.type}),
                }
            }
        }

        //// TODO: Handle virtual memory management later on
        logger.debug("Paging initialized", .{});
    }

    kernel.physical_address_space.log_free_memory();

    {
        const response = bootloader_framebuffer.response orelse @panic("Framebuffer response not found");
        if (response.framebuffer_count == 0) @panic("No framebuffer found");
        const ptr_framebuffer_ptr = response.framebuffers orelse @panic("Framebuffer response has an invalid pointer");
        const framebuffer_ptr = ptr_framebuffer_ptr.*;
        const framebuffers = framebuffer_ptr[0..response.framebuffer_count];
        const framebuffer = framebuffers[0];

        assert(framebuffers.len == 1);
        assert(framebuffer.pitch % framebuffer.width == 0);
        assert(framebuffer.bpp % @bitSizeOf(u8) == 0);
        const bytes_per_pixel = @intCast(u8, framebuffer.bpp / @bitSizeOf(u8));
        assert(framebuffer.pitch / framebuffer.width == bytes_per_pixel);

        // For now ignore virtual address since we are using our own mapping
        // TODO: make sure there is just an entry here
        const framebuffer_physical_address = blk: {
            for (memory_map_entries) |entry| {
                if (entry.type == .framebuffer) {
                    break :blk PhysicalAddress.new(entry.address);
                }
            }

            unreachable;
        };

        const framebuffer_virtual_address = framebuffer_physical_address.to_higher_half_virtual_address();
        const mapped_address = kernel.virtual_address_space.translate_address(framebuffer_virtual_address) orelse unreachable;
        assert(mapped_address.value == framebuffer_physical_address.value);

        kernel.bootloader_framebuffer = .{ .area = .{
            .bytes = @intToPtr([*]u8, framebuffer.address),
            .width = @intCast(u32, framebuffer.width),
            .height = @intCast(u32, framebuffer.height),
            .stride = @intCast(u32, framebuffer.bpp * framebuffer.width),
        } };

        logger.debug("Processed framebuffer", .{});
    }

    {
        const limine_cpus = blk: {
            const response = bootloader_smp.response orelse @panic("SMP response not found");
            assert(kernel.memory.cpus.items[0].lapic.id == response.bsp_lapic_id);
            const cpu_count = response.cpu_count;
            if (cpu_count == 0) @panic("SMP response has no CPU information");
            const ptr_cpu_ptr = response.cpus orelse @panic("SMP response has an invalid pointer to CPU data structures");
            const cpu_ptr = ptr_cpu_ptr.*;
            break :blk cpu_ptr[0..cpu_count];
        };

        const cpu_count = limine_cpus.len;
        logger.debug("CPU count: {}", .{cpu_count});
        const ap_cpu_count = cpu_count - 1;
        logger.debug("AP CPU count: {}", .{ap_cpu_count});
        const ap_threads = kernel.memory.threads.allocate_contiguously(kernel.virtual_address_space.heap.allocator, ap_cpu_count) catch @panic("wtf");
        const bsp_thread = TLS.get_current();
        logger.debug("Bsp thread: {*}", .{bsp_thread});
        logger.debug("Ap threads: {*}", .{ap_threads.ptr});
        assert((@ptrToInt(ap_threads.ptr) - @sizeOf(Thread)) == @ptrToInt(bsp_thread));
        const threads = kernel.memory.threads.static.array[0..kernel.memory.threads.len];

        const thread_stack_size = Scheduler.default_kernel_stack_size;
        const thread_bulk_stack_allocation_size = threads.len * thread_stack_size;
        const thread_stacks = kernel.virtual_address_space.allocate(thread_bulk_stack_allocation_size, null, .{ .write = true }) catch @panic("wtF");
        logger.debug("Current CPUs before adding AP: {}", .{kernel.memory.cpus.items.len});
        const ap_cpus = kernel.memory.cpus.add_many(ap_cpu_count) catch @panic("Unable to allocate cpus");
        _ = ap_cpus;
        assert(kernel.memory.cpus.items[0].id == limine_cpus[0].processor_id);

        // Map LAPIC address on just one CPU (since it's global)
        CPU.map_lapic();

        kernel.scheduler.lock.acquire();

        logger.debug("CPU thread count: {}", .{threads.len});
        // TODO: figure out stacks
        // TODO: ignore BSP cpu when AP initialization?
        for (threads) |*thread, thread_i| {
            const smp = &limine_cpus[thread_i];
            const cpu = &kernel.memory.cpus.items[thread_i];

            const stack_allocation_offset = thread_i * thread_stack_size;
            const kernel_stack_address = thread_stacks.offset(stack_allocation_offset);
            const thread_stack = Scheduler.ThreadStack{
                .kernel = .{ .address = kernel_stack_address, .size = thread_stack_size },
                .user = .{ .address = kernel_stack_address, .size = thread_stack_size },
            };

            const entry_point = &kernel_smp_entry;
            kernel.scheduler.initialize_thread(thread, thread_i, .kernel, .idle, @ptrToInt(entry_point), thread_stack, kernel.process);

            cpu.id = smp.processor_id;
            cpu.idle_thread = thread;
            cpu.lapic.id = smp.lapic_id;
            TLS.set_current(thread, cpu);
            smp.goto_address = entry_point;
        }

        // TODO: TSS

        // Update bsp CPU
        // TODO: maybe this is necessary?
        kernel.scheduler.lock.release();

        logger.debug("Processed SMP info", .{});
    }

    const current_thread = TLS.get_current();
    const cpu = current_thread.cpu orelse @panic("cpu");
    cpu.start();

    _ = kernel.scheduler.spawn_kernel_thread(.{ .address = @ptrToInt(&kernel.main) }) catch unreachable;

    logger.debug("Congrats! Reached to the end", .{});
    cpu.ready = true;
    cpu.make_thread_idle();
}

export fn kernel_smp_entry(smp_info: *Limine.SMPInfo) callconv(.C) noreturn {
    const cpu_index = smp_info.processor_id;
    // Current thread is already set in the process_smp function
    TLS.preset(&kernel.memory.cpus.items[cpu_index]);
    kernel.virtual_address_space.make_current();
    const current_thread = TLS.get_current();
    const cpu = current_thread.cpu orelse @panic("cpu");
    cpu.start();
    logger.debug("CPU started", .{});

    while (!cpu.ready) {
        cpu.lapic.next_timer(10);
        asm volatile (
            \\sti
            \\pause
            \\hlt
        );
    }

    logger.debug("cpu is now ready", .{});
    cpu.make_thread_idle();
}

// TODO: is this necessary?
var foo: Thread = undefined;
var foo2: Context = undefined;

export var bootloader_info = Limine.BootloaderInfo.Request{
    .revision = 0,
};

export var bootloader_hhdm = Limine.HHDM.Request{
    .revision = 0,
};

pub export var bootloader_framebuffer = Limine.Framebuffer.Request{
    .revision = 0,
};

export var bootloader_smp = Limine.SMPInfoRequest{
    .revision = 0,
    .flags = 0,
};

export var bootloader_memory_map = Limine.MemoryMap.Request{
    .revision = 0,
};

export var bootloader_entry_point = Limine.EntryPoint.Request{
    .revision = 0,
    .entry_point = kernel_entry_point,
};

export var bootloader_kernel_file = Limine.KernelFile.Request{
    .revision = 0,
};

export var bootloader_rsdp = Limine.RSDP.Request{
    .revision = 0,
};

export var bootloader_boot_time = Limine.BootTime.Request{
    .revision = 0,
};

export var bootloader_kernel_address = Limine.KernelAddress.Request{
    .revision = 0,
};

export var bootloader_modules = Limine.Module.Request{
    .revision = 0,
};

fn map_section(comptime section_name: []const u8, kernel_base_physical_address: PhysicalAddress, kernel_base_virtual_address: VirtualAddress, flags: VirtualAddressSpace.Flags) void {
    const section_start = @extern(*u8, .{ .name = section_name ++ "_section_start" });
    const section_end = @extern(*u8, .{ .name = section_name ++ "_section_end" });

    const virtual_address = VirtualAddress.new(@ptrToInt(section_start));
    const physical_address = PhysicalAddress.new(virtual_address.value - kernel_base_virtual_address.value + kernel_base_physical_address.value);
    const size = @ptrToInt(section_end) - @ptrToInt(section_start);
    const page_count = @divExact(size, x86_64.page_size);

    logger.debug("Mapping kernel section {s} ({}, {}) ({}, {})", .{ section_name, physical_address, physical_address.offset(size), virtual_address, virtual_address.offset(size) });
    VAS.bootstrap_map(physical_address, virtual_address, page_count, flags);
}

/// Define root.log_level to override the default
pub const log_level: common.log.Level = switch (common.build_mode) {
    .Debug => .debug,
    .ReleaseSafe => .debug,
    .ReleaseFast, .ReleaseSmall => .debug,
};

pub fn log(comptime level: common.log.Level, comptime scope: @TypeOf(.EnumLiteral), comptime format: []const u8, args: anytype) void {
    const scope_prefix = if (scope == .default) ": " else "(" ++ @tagName(scope) ++ "): ";
    const prefix = "[" ++ @tagName(level) ++ "] " ++ scope_prefix;
    arch.writer_lock.acquire();
    defer arch.writer_lock.release();

    const current_thread = TLS.get_current();

    arch.writer.writeAll("[Kernel] ") catch unreachable;
    if (current_thread.cpu) |current_cpu| {
        arch.writer.print("[Core #{}] ", .{current_cpu.id}) catch unreachable;
    } else {
        arch.writer.writeAll("[WARNING: unknown core] ") catch unreachable;
    }
    arch.writer.print("[Process #{}] [Thread #{}] ", .{ current_thread.process.id, current_thread.id }) catch unreachable;

    arch.writer.writeAll(prefix) catch unreachable;
    arch.writer.print(format, args) catch unreachable;
    arch.writer.writeByte('\n') catch unreachable;
}

pub fn panic(message: []const u8, _: ?*common.StackTrace, _: ?usize) noreturn {
    RNU.panic_extended("{s}", .{message}, @returnAddress(), @frameAddress());
}

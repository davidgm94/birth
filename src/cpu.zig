const lib = @import("lib");
const Allocator = lib.Allocator;
const assert = lib.assert;
const log = lib.log;

const privileged = @import("privileged");
const Mapping = privileged.Mapping;
const PageAllocator = privileged.PageAllocator;
const PageAllocatorInterface = privileged.PageAllocatorInterface;
const PhysicalAddress = privileged.PhysicalAddress;
const PhysicalAddressSpace = privileged.PhysicalAddressSpace;
const PhysicalMemoryRegion = privileged.PhysicalMemoryRegion;
const VirtualAddress = privileged.VirtualAddress;

const bootloader = @import("bootloader");

pub const test_runner = @import("cpu/test_runner.zig");

pub const arch = @import("cpu/arch.zig");

pub export var stack: [0x4000]u8 align(0x1000) = undefined;
pub export var address_space: VirtualAddressSpace = undefined;

pub export var mappings: extern struct {
    text: privileged.Mapping = .{},
    rodata: privileged.Mapping = .{},
    data: privileged.Mapping = .{},
} = .{};

pub export var page_allocator = PageAllocator{
    .head = null,
    .list_allocator = .{
        .u = .{
            .primitive = .{
                .backing_4k_page = undefined,
                .allocated = 0,
            },
        },
        .primitive = true,
    },
};

pub const writer = arch.writer;
var panic_lock = arch.Spinlock.released;

pub fn panic(comptime format: []const u8, arguments: anytype) noreturn {
    privileged.arch.disableInterrupts();

    panic_lock.acquire();
    writer.writeAll("[CPU DRIVER] [PANIC] ") catch unreachable;
    writer.print(format, arguments) catch unreachable;
    writer.writeByte('\n') catch unreachable;
    privileged.arch.stopCPU();

    panic_lock.release();

    if (lib.is_test) {
        privileged.exitFromQEMU(.failure);
    } else {
        privileged.arch.stopCPU();
    }
}

pub const UserVirtualAddressSpace = extern struct {
    generic: VirtualAddressSpace,
};

pub const VirtualAddressSpace = extern struct {
    arch: paging.Specific,
    page: Page = .{},
    heap: Heap = .{},
    options: packed struct(u64) {
        user: bool,
        mapped_page_tables: bool,
        log_pages: bool,
        reserved: u61 = 0,
    },

    const Context = extern struct {
        region_base: u64 = 0,
        size: u64 = 0,
    };

    const Page = extern struct {
        context: Context = .{},
        log: ?*PageAllocator.Entry = null,
        log_count: u64 = 0,
    };

    const Heap = extern struct {
        context: Context = .{},

        pub fn allocate(heap: *Heap, comptime T: type) Allocator.Allocate.Error!*T {
            if (heap.context.size == 0) {
                const virtual_address_space = @fieldParentPtr(VirtualAddressSpace, "heap", heap);
                const result = try page_allocator.allocate(lib.arch.valid_page_sizes[0], lib.arch.valid_page_sizes[0]);
                virtual_address_space.heap.context = .{
                    .region_base = result.address.toHigherHalfVirtualAddress().value(),
                    .size = result.size,
                };
            }

            if (heap.context.size < @sizeOf(T)) {
                @panic("size");
            }
            if (!lib.isAligned(heap.context.region_base, @alignOf(T))) {
                @panic("alignment");
            }

            const result = @intToPtr(*T, heap.context.region_base);

            heap.context.region_base += @sizeOf(T);
            heap.context.size -= @sizeOf(T);

            return result;
        }
    };

    const VAS = @This();

    pub const paging = switch (lib.cpu.arch) {
        .x86 => privileged.arch.x86_64.paging,
        else => privileged.arch.current.paging,
    };

    fn callbackHeapAllocate(allocator: *Allocator, size: u64, alignment: u64) Allocator.Allocate.Error!Allocator.Allocate.Result {
        _ = alignment;
        _ = size;
        if (lib.cpu.arch != .x86) {
            const virtual_address_space = @fieldParentPtr(VirtualAddressSpace, "heap", @fieldParentPtr(Heap, "allocator", allocator));
            _ = virtual_address_space;
        } else {
            return Allocator.Allocate.Error.OutOfMemory;
        }
    }
    //

    pub fn user(physical_address_space: *PhysicalAddressSpace) VAS {
        // TODO: defer memory free when this produces an error
        // TODO: Maybe consume just the necessary space? We are doing this to avoid branches in the kernel heap allocator
        var vas = VAS{
            .arch = undefined,
        };

        paging.init_user(&vas, physical_address_space);

        return vas;
    }

    pub inline fn makeCurrent(vas: *const VAS) void {
        paging.makeCurrent(vas);
    }

    pub fn map(virtual_address_space: *VirtualAddressSpace, asked_physical_address: PhysicalAddress, asked_virtual_address: VirtualAddress, size: u64, general_flags: Mapping.Flags) !void {
        // TODO: use flags
        log.debug("Mapping 0x{x}-0x{x} to 0x{x}-0x{x}", .{ asked_physical_address.value(), asked_physical_address.offset(size).value(), asked_virtual_address.value(), asked_virtual_address.offset(size).value() });

        // if (!asked_physical_address.isValid()) return Error.invalid_physical;
        // if (!asked_virtual_address.isValid()) return Error.invalid_virtual;
        if (size == 0) {
            return paging.Error.invalid_size;
        }

        if (!lib.isAlignedGeneric(u64, asked_physical_address.value(), lib.arch.valid_page_sizes[0])) {
            return paging.Error.unaligned_physical;
        }

        if (!lib.isAlignedGeneric(u64, asked_virtual_address.value(), lib.arch.valid_page_sizes[0])) {
            return paging.Error.unaligned_virtual;
        }

        if (!lib.isAlignedGeneric(u64, size, lib.arch.valid_page_sizes[0])) {
            return paging.Error.unaligned_size;
        }

        if (asked_physical_address.value() >= lib.config.cpu_driver_higher_half_address) {
            return paging.Error.invalid_physical;
        }

        log.debug("Mapping 0x{x} -> 0x{x} for 0x{x} bytes in 0x{x}", .{ asked_virtual_address.value(), asked_physical_address.value(), size, virtual_address_space.arch.cr3.getAddress().value() });

        try virtual_address_space.arch.map(asked_physical_address, asked_virtual_address, size, general_flags, virtual_address_space.getPageAllocatorInterface());
    }

    pub inline fn mapDevice(virtual_address_space: *VirtualAddressSpace, asked_physical_address: PhysicalAddress, size: u64) !VirtualAddress {
        try virtual_address_space.map(asked_physical_address, asked_physical_address.toHigherHalfVirtualAddress(), size, .{
            .write = true,
            .cache_disable = true,
            .global = false,
        });

        return asked_physical_address.toHigherHalfVirtualAddress();
    }

    pub fn allocatePages(virtual_address_space: *VirtualAddressSpace, size: u64, alignment: u64) Allocator.Allocate.Error!PhysicalMemoryRegion {
        if (virtual_address_space.page.context.size == 0) {
            if (alignment > lib.arch.valid_page_sizes[1]) return Allocator.Allocate.Error.OutOfMemory;
            // Try to allocate a bigger bulk so we don't have to use the backing allocator (slower) everytime a page is needed
            const selected_size = @max(size, lib.arch.valid_page_sizes[1]);
            const selected_alignment = @max(alignment, lib.arch.valid_page_sizes[1]);

            const page_bulk_allocation = page_allocator.allocate(selected_size, selected_alignment) catch blk: {
                if (alignment > lib.arch.valid_page_sizes[0]) return Allocator.Allocate.Error.OutOfMemory;
                break :blk try page_allocator.allocate(size, alignment);
            };
            virtual_address_space.page.context = .{
                .region_base = page_bulk_allocation.address.value(),
                .size = page_bulk_allocation.size,
            };

            if (virtual_address_space.options.log_pages) {
                try virtual_address_space.addPage(page_bulk_allocation);
            }
        }

        assert(virtual_address_space.page.context.region_base != 0);

        const allocation_result = .{
            .address = PhysicalAddress.new(virtual_address_space.page.context.region_base),
            .size = size,
        };

        if (!lib.isAlignedGeneric(u64, allocation_result.address.value(), alignment)) return Allocator.Allocate.Error.OutOfMemory;

        virtual_address_space.page.context.region_base += size;
        virtual_address_space.page.context.size -= size;

        return allocation_result;
    }
    fn callbackAllocatePages(context: ?*anyopaque, size: u64, alignment: u64) Allocator.Allocate.Error!PhysicalMemoryRegion {
        const virtual_address_space = @ptrCast(*VirtualAddressSpace, @alignCast(@alignOf(VirtualAddressSpace), context));
        return try virtual_address_space.allocatePages(size, alignment);
    }

    pub fn mapPageTables(virtual_address_space: *VirtualAddressSpace) !void {
        assert(virtual_address_space.options.log_pages);

        log.debug("log count: {}", .{virtual_address_space.page.log_count});
        var maybe_page_table_entry = virtual_address_space.page.log;
        while (maybe_page_table_entry) |page_table_entry| : (maybe_page_table_entry = page_table_entry.next) {
            try virtual_address_space.map(page_table_entry.region.address, page_table_entry.region.address.toIdentityMappedVirtualAddress(), page_table_entry.region.size, .{
                .user = true,
                .write = true,
            });
        }
        assert(virtual_address_space.page.log.?.next == null);
        log.debug("log count: {}", .{virtual_address_space.page.log_count});

        virtual_address_space.options.mapped_page_tables = true;
    }

    pub fn addPage(virtual_address_space: *VirtualAddressSpace, region: PhysicalMemoryRegion) !void {
        const new_entry = try virtual_address_space.heap.allocate(PageAllocator.Entry);
        new_entry.* = .{
            .region = region,
            .next = virtual_address_space.page.log,
        };
        virtual_address_space.page.log = new_entry;

        virtual_address_space.page.log_count += 1;
    }

    pub inline fn validate(virtual_address_space: *VirtualAddressSpace) !void {
        log.debug("Performing virtual address space validation...", .{});
        try paging.validate(virtual_address_space);
    }

    pub inline fn translateAddress(virtual_address_space: *VirtualAddressSpace, virtual_address: VirtualAddress) !PhysicalAddress {
        const physical_address = try paging.translateAddress(virtual_address_space.arch, virtual_address);
        return physical_address;
    }

    pub fn getPageAllocatorInterface(virtual_address_space: *VirtualAddressSpace) PageAllocatorInterface {
        return .{
            .allocate = VirtualAddressSpace.callbackAllocatePages,
            .context = virtual_address_space,
            .context_type = .cpu,
        };
    }
};

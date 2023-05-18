// This package provides of privileged data structures and routines to both kernel and bootloaders, for now

const lib = @import("lib");
const assert = lib.assert;
const log = lib.log;
const maxInt = lib.maxInt;
const Allocator = lib.Allocator;

const bootloader = @import("bootloader");

pub const ACPI = @import("privileged/acpi.zig");
pub const arch = @import("privileged/arch.zig");

pub const E9WriterError = error{};
pub const E9Writer = lib.Writer(void, E9WriterError, writeToE9);
pub const writer = E9Writer{ .context = {} };

fn writeToE9(_: void, bytes: []const u8) E9WriterError!usize {
    return arch.io.writeBytes(0xe9, bytes);
}

pub const default_stack_size = 0x4000;

pub const ResourceOwner = enum(u2) {
    bootloader = 0,
    kernel = 1,
    user = 2,
};

const panic_logger = lib.log.scoped(.PANIC);

pub inline fn exitFromQEMU(exit_code: lib.QEMU.ExitCode) noreturn {
    comptime assert(@sizeOf(lib.QEMU.ExitCode) == @sizeOf(u32));
    arch.io.write(u32, lib.QEMU.isa_debug_exit.io_base, @enumToInt(exit_code));

    arch.stopCPU();
}

fn getAddrT(comptime AddressEnum: type) type {
    const type_info = @typeInfo(AddressEnum);
    assert(type_info == .Enum);
    const AddrT = type_info.Enum.tag_type;
    assert(switch (lib.cpu.arch) {
        .x86 => @sizeOf(AddrT) == 2 * @sizeOf(usize),
        else => @sizeOf(AddrT) == @sizeOf(usize),
    });

    return AddrT;
}

pub fn AddressInterface(comptime AddressEnum: type) type {
    const AddrT = getAddrT(AddressEnum);
    const Addr = AddressEnum;

    const Result = struct {
        pub inline fn newNoChecks(addr: AddrT) Addr {
            return @intToEnum(Addr, addr);
        }

        pub inline fn invalid() Addr {
            return newNoChecks(0);
        }

        pub inline fn value(addr: Addr) AddrT {
            return @enumToInt(addr);
        }

        pub inline fn offset(addr: Addr, asked_offset: AddrT) Addr {
            return newNoChecks(addr.value() + asked_offset);
        }

        pub inline fn negativeOffset(addr: Addr, asked_offset: AddrT) Addr {
            return newNoChecks(addr.value() - asked_offset);
        }

        pub inline fn addOffset(addr: *Addr, asked_offset: AddrT) void {
            addr.* = addr.offset(asked_offset);
        }

        pub inline fn subOffset(addr: *Addr, asked_offset: AddrT) void {
            addr.* = addr.negativeOffset(asked_offset);
        }

        pub inline fn isAligned(addr: Addr, alignment: u64) bool {
            const alignment_mask = alignment - 1;
            return addr.value() & alignment_mask == 0;
        }
    };

    return Result;
}

pub const PhysicalAddress = enum(u64) {
    null = 0,
    _,
    const PA = @This();

    pub usingnamespace AddressInterface(@This());

    pub inline fn new(address: u64) PA {
        if (address >= lib.config.cpu_driver_higher_half_address) @panic("Trying to write a higher half virtual address value into a physical address");
        return @intToEnum(PA, address);
    }

    pub inline fn toIdentityMappedVirtualAddress(physical_address: PA) VirtualAddress {
        return VirtualAddress.new(physical_address.value());
    }

    pub inline fn toHigherHalfVirtualAddress(physical_address: PA) VirtualAddress {
        return physical_address.toIdentityMappedVirtualAddress().offset(lib.config.cpu_driver_higher_half_address);
    }
};

pub const VirtualAddress = enum(u64) {
    null = 0,
    _,

    pub usingnamespace AddressInterface(@This());

    pub inline fn new(address: u64) VirtualAddress {
        return @intToEnum(VirtualAddress, address);
    }

    pub inline fn access(virtual_address: VirtualAddress, comptime Ptr: type) Ptr {
        return @intToPtr(Ptr, lib.safeArchitectureCast(virtual_address.value()));
    }

    pub inline fn isValid(virtual_address: VirtualAddress) bool {
        _ = virtual_address;
        return true;
    }

    pub inline fn toPhysicalAddress(virtual_address: VirtualAddress) PhysicalAddress {
        assert(virtual_address.value() >= lib.config.cpu_driver_higher_half_address);
        return @intToEnum(PhysicalAddress, virtual_address.value() - lib.config.cpu_driver_higher_half_address);
    }

    pub inline fn toGuaranteedPhysicalAddress(virtual_address: VirtualAddress) PhysicalAddress {
        assert(virtual_address.value() < lib.config.cpu_driver_higher_half_address);
        return PhysicalAddress.new(virtual_address.value());
    }
};

pub fn RegionInterface(comptime Region: type) type {
    const type_info = @typeInfo(Region);
    assert(type_info == .Struct);
    assert(type_info.Struct.layout == .Extern);
    assert(type_info.Struct.fields.len == 2);
    const fields = type_info.Struct.fields;
    assert(lib.equal(u8, fields[0].name, "address"));
    assert(lib.equal(u8, fields[1].name, "size"));
    const Addr = fields[0].type;
    const AddrT = getAddrT(Addr);

    return struct {
        pub inline fn new(address: Addr, size: AddrT) Region {
            return Region{
                .address = address,
                .size = size,
            };
        }

        pub inline fn fromRaw(raw_address: AddrT, size: AddrT) Region {
            const address = Addr.new(raw_address);
            return new(address, size);
        }

        pub inline fn fromAllocation(allocation: Allocator.Allocate.Result) Region {
            return new(addressToAddrT(allocation.address), allocation.size);
        }

        inline fn addressToAddrT(address: AddrT) Addr {
            return if (Region == PhysicalMemoryRegion and address >= lib.config.cpu_driver_higher_half_address) VirtualAddress.new(address).toPhysicalAddress() else Addr.new(address);
        }

        pub inline fn fromByteSlice(slice: []const u8) Region {
            return new(addressToAddrT(@ptrToInt(slice.ptr)), slice.len);
        }

        pub inline fn offset(region: Region, asked_offset: AddrT) Region {
            const address = region.address.offset(asked_offset);
            const size = region.size - asked_offset;
            return Region{
                .address = address,
                .size = size,
            };
        }

        pub inline fn top(region: Region) Addr {
            return region.address.offset(region.size);
        }

        pub inline fn takeSlice(region: *Region, size: AddrT) Region {
            assert(size <= region.size);
            const result = Region{
                .address = region.address,
                .size = size,
            };
            region.* = region.offset(size);

            return result;
        }

        pub inline fn split(region: Region, comptime count: comptime_int) [count]Region {
            const region_size = @divExact(region.size, count);
            var result: [count]Region = undefined;
            var address = region.address;
            var region_offset: u64 = 0;
            inline for (&result) |*split_region| {
                split_region.* = Region{
                    .address = address.offset(region_offset),
                    .size = region_size,
                };
                region_offset += region_size;
            }

            return result;
        }
    };
}

pub const PhysicalMemoryRegion = extern struct {
    address: PhysicalAddress,
    size: u64,

    pub usingnamespace RegionInterface(@This()); // This is so cool

    pub inline fn toIdentityMappedVirtualAddress(physical_memory_region: PhysicalMemoryRegion) VirtualMemoryRegion {
        return .{
            .address = physical_memory_region.address.toIdentityMappedVirtualAddress(),
            .size = physical_memory_region.size,
        };
    }

    pub inline fn toHigherHalfVirtualAddress(physical_memory_region: PhysicalMemoryRegion) VirtualMemoryRegion {
        return .{
            .address = physical_memory_region.address.toHigherHalfVirtualAddress(),
            .size = physical_memory_region.size,
        };
    }
};

pub const VirtualMemoryRegion = extern struct {
    address: VirtualAddress,
    size: u64,

    pub usingnamespace RegionInterface(@This());

    pub inline fn access(virtual_memory_region: VirtualMemoryRegion, comptime T: type) []T {
        const slice_len = @divExact(virtual_memory_region.size, @sizeOf(T));
        const result = virtual_memory_region.address.access([*]T)[0..lib.safeArchitectureCast(slice_len)];
        return result;
    }

    pub inline fn takeByteSlice(virtual_memory_region: *VirtualMemoryRegion, size: u64) []u8 {
        return virtual_memory_region.takeSlice(size).access(u8);
    }
};

pub const Mapping = extern struct {
    physical: PhysicalAddress = PhysicalAddress.invalid(),
    virtual: VirtualAddress = .null,
    size: u64 = 0,
    flags: Flags = .{},
    reserved: u32 = 0,

    pub const Flags = packed struct(u32) {
        write: bool = false,
        cache_disable: bool = false,
        global: bool = false,
        execute: bool = false,
        user: bool = false,
        secret: bool = false,
        reserved: u26 = 0,

        pub inline fn empty() Flags {
            return .{};
        }

        pub inline fn toArchitectureSpecific(flags: Flags) arch.paging.MemoryFlags {
            return arch.paging.newFlags(flags);
        }
    };
};

pub const PageAllocator = struct {
    allocate: *const fn (context: ?*anyopaque, size: u64, alignment: u64, allocate_options: AllocateOptions) Allocator.Allocate.Error!PhysicalMemoryRegion,
    context: ?*anyopaque,
    context_type: ContextType,
    reserved: u32 = 0,

    pub const AllocatePageTablesOptions = packed struct {
        count: u16 = 1,
        level: arch.paging.Level,
        user: bool,
    };

    pub inline fn allocatePageTable(page_allocator: PageAllocator, options: AllocatePageTablesOptions) !PhysicalMemoryRegion {
        const result = try page_allocator.allocate(page_allocator.context, arch.paging.page_table_size, arch.paging.page_table_alignment, .{
            .count = options.count,
            .level = options.level,
            .level_valid = true,
            .user = options.user,
        });
        return result;
    }

    pub const AllocateOptions = packed struct {
        count: u16 = 1,
        space_waste_allowed_to_guarantee_alignment: u8 = 0,
        level: arch.paging.Level = undefined,
        level_valid: bool = false,
        user: bool = false,
    };

    const ContextType = enum(u32) {
        invalid = 0,
        bootloader = 1,
        cpu = 2,
    };
};

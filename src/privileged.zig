const common = @import("common");
const assert = common.assert;

// This package provides of privileged data structures and routines to both kernel and bootloaders, for now
// TODO: implement properly
//const crash = @import("privileged/crash.zig");
//pub const panic = crash.panic;
//pub const panic_extended = crash.panic_extended;

pub const arch = @import("privileged/arch.zig");
pub const Capabilities = @import("privileged/capabilities.zig");
pub const Heap = @import("privileged/heap.zig");
pub const MappingDatabase = @import("privileged/mapping_database.zig");
pub const PhysicalAddressSpace = @import("privileged/physical_address_space.zig");
pub const UEFI = @import("privileged/uefi.zig");
pub const VirtualAddressSpace = @import("privileged/virtual_address_space.zig");

pub const ResourceOwner = enum(u2) {
    bootloader = 0,
    kernel = 1,
    user = 2,
};

pub const CoreSupervisor = struct {
    is_valid: bool,
    next: ?*CoreSupervisor,
    previous: ?*CoreSupervisor,
    mdb_root: VirtualAddress(.local),
    init_rootcn: Capabilities.CTE,
    scheduler_type: SchedulerType,
    scheduler_state: union(SchedulerType) {
        round_robin: RoundRobin,
        rate_based_earliest_deadline: RBED,
    },
    kernel_offset: i64,
    irq_in_use: [arch.dispatch_count]u8, // bitmap of handed out caps
    irq_dispatch: [arch.dispatch_count]Capabilities.CTE,
    pending_ram_in_use: u8,
    pending_ram: [4]RAM,
};

const RAM = struct {
    base: u64,
    bytes: u64,
};

pub const RoundRobin = struct {
    current: ?*CoreDirector,
};

pub const RBED = struct {
    queue_head: ?*CoreDirector,
    queue_tail: ?*CoreDirector,
    // TODO: more stuff
};

pub const SchedulerType = enum {
    round_robin,
    rate_based_earliest_deadline,
};

pub const CoreDirector = struct {
    fp: u64,
    disabled: bool,
};

pub const CoreLocality = enum {
    local,
    global,
};

pub fn PhysicalAddress(comptime locality: CoreLocality) type {
    return enum(usize) {
        null = 0,
        _,

        const PA = @This();

        pub fn new(new_value: usize) PA {
            const physical_address = @intToEnum(PA, new_value);

            if (!physical_address.is_valid()) {
                @panic("Physical address is invalid");
            }

            return physical_address;
        }

        pub fn temporary_invalid() PA {
            return maybe_invalid(0);
        }

        pub fn maybe_invalid(new_value: usize) PA {
            return @intToEnum(PA, new_value);
        }

        pub fn is_valid(physical_address: PA) bool {
            if (physical_address == PA.null) return false;

            assert(arch.max_physical_address_bit != 0);
            const max = @as(usize, 1) << arch.max_physical_address_bit;
            assert(max > common.max_int(u32));

            return physical_address.value() <= max;
        }

        pub fn value(physical_address: PA) usize {
            return @enumToInt(physical_address);
        }

        pub fn is_equal(physical_address: PA, other: PA) bool {
            return physical_address.value == other.value;
        }

        pub fn is_aligned(physical_address: PA, alignment: usize) bool {
            return common.is_aligned(physical_address.value(), alignment);
        }

        pub fn belongs_to_region(physical_address: PA, region: PhysicalMemoryRegion) bool {
            return physical_address.value >= region.address.value and physical_address.value < region.address.value + region.size;
        }

        pub fn offset(physical_address: PA, asked_offset: usize) PA {
            return @intToEnum(PA, @enumToInt(physical_address) + asked_offset);
        }

        pub fn add_offset(physical_address: *PA, asked_offset: usize) void {
            physical_address.* = physical_address.offset(asked_offset);
        }

        pub fn aligned_forward(physical_address: PA, alignment: usize) PA {
            return @intToEnum(PA, common.align_forward(physical_address.value(), alignment));
        }

        pub fn aligned_backward(physical_address: PA, alignment: usize) PA {
            return @intToEnum(PA, common.align_backward(physical_address.value(), alignment));
        }

        pub fn align_forward(physical_address: *PA, alignment: usize) void {
            physical_address.* = physical_address.aligned_forward(alignment);
        }

        pub fn align_backward(physical_address: *PA, alignment: usize) void {
            physical_address.* = physical_address.aligned_backward(alignment);
        }

        pub fn to_identity_mapped_virtual_address(physical_address: PA) VirtualAddress(locality) {
            return VirtualAddress(locality).new(physical_address.value());
        }

        pub fn to_higher_half_virtual_address(physical_address: PA) VirtualAddress(locality) {
            const address = VirtualAddress(locality).new(physical_address.value() + common.config.kernel_higher_half_address);
            return address;
        }

        pub fn to_global(physical_address: PA) PhysicalAddress(.global) {
            comptime {
                assert(locality == .local);
            }
            return @intToEnum(PhysicalAddress(.global), @enumToInt(physical_address));
        }

        pub fn to_local(physical_address: PA) PhysicalAddress(.local) {
            comptime {
                assert(locality == .global);
            }
            return @intToEnum(PhysicalAddress(.local), @enumToInt(physical_address));
        }

        pub fn format(physical_address: PA, comptime _: []const u8, _: common.InternalFormatOptions, writer: anytype) @TypeOf(writer).Error!void {
            try common.internal_format(writer, "0x{x}", .{physical_address.value()});
        }
    };
}

pub fn VirtualAddress(comptime locality: CoreLocality) type {
    _ = locality;
    return enum(usize) {
        null = 0,
        _,

        const VA = @This();

        pub fn new(new_value: usize) VA {
            const virtual_address = @intToEnum(VA, new_value);
            assert(virtual_address.is_valid());
            return virtual_address;
        }

        pub fn invalid() VA {
            return VA.null;
        }

        pub fn value(virtual_address: VA) usize {
            return @enumToInt(virtual_address);
        }

        pub fn is_valid(virtual_address: VA) bool {
            return virtual_address != VA.null;
        }

        pub fn access(virtual_address: VA, comptime Ptr: type) Ptr {
            return @intToPtr(Ptr, virtual_address.value());
        }

        pub fn offset(virtual_address: VA, asked_offset: usize) VA {
            return @intToEnum(VA, virtual_address.value() + asked_offset);
        }

        pub fn add_offset(virtual_address: *VA, asked_offset: usize) void {
            virtual_address.* = virtual_address.offset(asked_offset);
        }

        pub fn aligned_forward(virtual_address: VA, alignment: usize) VA {
            return @intToEnum(VA, common.align_forward(virtual_address.value(), alignment));
        }

        pub fn aligned_backward(virtual_address: VA, alignment: usize) VA {
            return @intToEnum(VA, common.align_backward(virtual_address.value(), alignment));
        }

        pub fn align_forward(virtual_address: *VA, alignment: usize) void {
            virtual_address.* = virtual_address.aligned_forward(alignment);
        }

        pub fn align_backward(virtual_address: *VA, alignment: usize) void {
            virtual_address.* = virtual_address.aligned_backward(alignment);
        }

        pub fn is_aligned(virtual_address: VA, alignment: usize) bool {
            return common.is_aligned(virtual_address.value(), alignment);
        }

        pub fn format(virtual_address: VA, comptime _: []const u8, _: common.InternalFormatOptions, writer: anytype) @TypeOf(writer).Error!void {
            try common.internal_format(writer, "0x{x}", .{virtual_address.value()});
        }
    };
}

pub fn PhysicalMemoryRegion(comptime locality: CoreLocality) type {
    return struct {
        address: PhysicalAddress(locality),
        size: u64,

        const PMR = PhysicalMemoryRegion(locality);

        pub fn to_higher_half_virtual_address(physical_memory_region: PMR) VirtualMemoryRegion(locality) {
            return VirtualMemoryRegion(locality){
                .address = physical_memory_region.address.to_higher_half_virtual_address(),
                .size = physical_memory_region.size,
            };
        }

        pub fn to_identity_mapped_virtual_address(physical_memory_region: PMR) VirtualMemoryRegion(locality) {
            return VirtualMemoryRegion(locality){
                .address = physical_memory_region.address.to_identity_mapped_virtual_address(),
                .size = physical_memory_region.size,
            };
        }

        pub fn offset(physical_memory_region: PMR, asked_offset: u64) PMR {
            assert(asked_offset < physical_memory_region.size);

            var result = physical_memory_region;
            result.address = result.address.offset(asked_offset);
            result.size -= asked_offset;
            return result;
        }

        pub fn take_slice(physical_memory_region: PMR, size: u64) PMR {
            assert(size < physical_memory_region.size);

            var result = physical_memory_region;
            result.size = size;
            return result;
        }
    };
}

pub fn VirtualMemoryRegion(comptime locality: CoreLocality) type {
    return struct {
        address: VirtualAddress(locality),
        size: u64,

        const VMR = @This();

        pub fn new(address: VirtualAddress, size: u64) VMR {
            return VMR{
                .address = address,
                .size = size,
            };
        }

        pub fn access_bytes(virtual_memory_region: VMR) []u8 {
            return virtual_memory_region.address.access([*]u8)[0..virtual_memory_region.size];
        }

        pub fn access(virtual_memory_region: VMR, comptime T: type) []T {
            return virtual_memory_region.address.access([*]T)[0..@divExact(virtual_memory_region.size, @sizeOf(T))];
        }
    };
}

pub const PassId = u32;
pub const CoreId = u8;
pub const CapAddr = u32;

const CTE = Capabilities.CTE;
pub const SpawnState = struct {
    cnodes: struct {
        task: ?*CTE = null,
        seg: ?*CTE = null,
        super: ?*CTE = null,
        physical_address: ?*CTE = null,
        module: ?*CTE = null,
        page: ?*CTE = null,
        base_page: ?*CTE = null,
        early_cnode: ?*CTE = null,
        slot_alloc0: ?*CTE = null,
        slot_alloc1: ?*CTE = null,
        slot_alloc2: ?*CTE = null,
    } = .{},
    slots: struct {
        seg: Capabilities.Slot = 0,
        super: Capabilities.Slot = 0,
        physical_address: Capabilities.Slot = 0,
        module: Capabilities.Slot = 0,
    } = .{},
    argument_page_address: PhysicalAddress(.local) = .null,
};

pub fn panic(comptime format: []const u8, arguments: anytype) noreturn {
    const panic_logger = common.log.scoped(.PANIC);
    panic_logger.err(format, arguments);
    arch.CPU_stop();
}

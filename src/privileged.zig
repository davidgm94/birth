const common = @import("common");
const assert = common.assert;

// This package provides of privileged data structures and routines to both kernel and bootloaders, for now
const crash = @import("privileged/crash.zig");
pub const panic = crash.panic;
pub const panic_extended = crash.panic_extended;

pub const Heap = @import("privileged/heap.zig");
pub const MappingDatabase = @import("privileged/mapping_database.zig");
pub const PhysicalAddressSpace = @import("privileged/physical_address_space.zig");
pub const PhysicalMemoryRegion = @import("privileged/physical_memory_region.zig");
pub const UEFI = @import("privileged/uefi.zig");
pub const VirtualAddressSpace = @import("privileged/virtual_address_space.zig");
pub const VirtualMemoryRegion = @import("privileged/virtual_memory_region.zig");

pub const ResourceOwner = enum(u2) {
    bootloader = 0,
    kernel = 1,
    user = 2,
};

pub const CoreSupervisor = struct {
    is_valid: bool,
    next: ?*CoreSupervisor,
    previous: ?*CoreSupervisor,
    mdb_root: VirtualAddress,
    init_rootcn: CTE,
    scheduler_type: SchedulerType,
    scheduler_state: union(SchedulerType) {
        round_robin: RoundRobin,
        rate_based_earliest_deadline: RBED,
    },
    kernel_offset: i64,
    irq_in_use: [arch.dispatch_count]u8, // bitmap of handed out caps
    irq_dispatch: [arch.dispatch_count]CTE,
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

pub const CTE = struct {
    // TODO:
};

const arch = @import("arch");

pub const CoreDirector = struct {
    fp: u64,
    disabled: bool,
};

pub const PhysicalAddress = enum(usize) {
    null = 0,
    _,

    pub fn new(new_value: usize) PhysicalAddress {
        const physical_address = @intToEnum(PhysicalAddress, new_value);

        if (!physical_address.is_valid()) {
            @panic("Physical address is invalid");
        }

        return physical_address;
    }

    pub fn temporary_invalid() PhysicalAddress {
        return maybe_invalid(0);
    }

    pub fn maybe_invalid(new_value: usize) PhysicalAddress {
        return PhysicalAddress{
            .value = new_value,
        };
    }

    pub fn is_valid(physical_address: PhysicalAddress) bool {
        if (physical_address == PhysicalAddress.null) return false;

        assert(arch.max_physical_address_bit != 0);
        const max = @as(usize, 1) << arch.max_physical_address_bit;
        assert(max > common.max_int(u32));

        return physical_address.value() <= max;
    }

    pub fn value(physical_address: PhysicalAddress) usize {
        return @enumToInt(physical_address);
    }

    pub fn is_equal(physical_address: PhysicalAddress, other: PhysicalAddress) bool {
        return physical_address.value == other.value;
    }

    pub fn is_aligned(physical_address: PhysicalAddress, alignment: usize) bool {
        return common.is_aligned(physical_address.value(), alignment);
    }

    pub fn belongs_to_region(physical_address: PhysicalAddress, region: PhysicalMemoryRegion) bool {
        return physical_address.value >= region.address.value and physical_address.value < region.address.value + region.size;
    }

    pub fn offset(physical_address: PhysicalAddress, asked_offset: usize) PhysicalAddress {
        return @intToEnum(PhysicalAddress, @enumToInt(physical_address) + asked_offset);
    }

    pub fn add_offset(physical_address: *PhysicalAddress, asked_offset: usize) void {
        physical_address.* = physical_address.offset(asked_offset);
    }

    pub fn to_identity_mapped_virtual_address(physical_address: PhysicalAddress) VirtualAddress {
        return VirtualAddress.new(physical_address.value());
    }

    pub fn to_higher_half_virtual_address(physical_address: PhysicalAddress) VirtualAddress {
        const address = VirtualAddress.new(physical_address.value() + common.config.kernel_higher_half_address);
        return address;
    }

    //pub fn to_virtual_address_with_offset(physical_address: PhysicalAddress, asked_offset: usize) VirtualAddress {
    //return VirtualAddress.new(physical_address.value + asked_offset);
    //}

    pub fn aligned_forward(physical_address: PhysicalAddress, alignment: usize) PhysicalAddress {
        return @intToEnum(PhysicalAddress, common.align_forward(physical_address.value(), alignment));
    }

    pub fn aligned_backward(physical_address: PhysicalAddress, alignment: usize) PhysicalAddress {
        return @intToEnum(PhysicalAddress, common.align_backward(physical_address.value(), alignment));
    }

    pub fn align_forward(virtual_address: *VirtualAddress, alignment: usize) void {
        virtual_address.* = virtual_address.aligned_forward(alignment);
    }

    pub fn align_backward(virtual_address: *VirtualAddress, alignment: usize) void {
        virtual_address.* = virtual_address.aligned_backward(alignment);
    }

    pub fn format(physical_address: PhysicalAddress, comptime _: []const u8, _: common.InternalFormatOptions, writer: anytype) @TypeOf(writer).Error!void {
        try common.internal_format(writer, "0x{x}", .{physical_address.value()});
    }
};

pub const VirtualAddress = enum(usize) {
    null = 0,
    _,

    pub fn new(new_value: usize) VirtualAddress {
        const virtual_address = @intToEnum(VirtualAddress, new_value);
        assert(virtual_address.is_valid());
        return virtual_address;
    }

    pub fn invalid() VirtualAddress {
        return VirtualAddress.null;
    }

    pub fn value(virtual_address: VirtualAddress) usize {
        return @enumToInt(virtual_address);
    }

    pub fn is_valid(virtual_address: VirtualAddress) bool {
        return virtual_address != VirtualAddress.null;
    }

    pub fn access(virtual_address: VirtualAddress, comptime Ptr: type) Ptr {
        return @intToPtr(Ptr, virtual_address.value());
    }

    pub fn offset(virtual_address: VirtualAddress, asked_offset: usize) VirtualAddress {
        return @intToEnum(VirtualAddress, virtual_address.value() + asked_offset);
    }

    pub fn add_offset(virtual_address: *VirtualAddress, asked_offset: usize) void {
        virtual_address.* = virtual_address.offset(asked_offset);
    }

    pub fn aligned_forward(virtual_address: VirtualAddress, alignment: usize) VirtualAddress {
        return @intToEnum(VirtualAddress, common.align_forward(virtual_address.value(), alignment));
    }

    pub fn aligned_backward(virtual_address: VirtualAddress, alignment: usize) VirtualAddress {
        return @intToEnum(VirtualAddress, common.align_backward(virtual_address.value(), alignment));
    }

    pub fn align_forward(virtual_address: *VirtualAddress, alignment: usize) void {
        virtual_address.* = virtual_address.aligned_forward(alignment);
    }

    pub fn align_backward(virtual_address: *VirtualAddress, alignment: usize) void {
        virtual_address.* = virtual_address.aligned_backward(alignment);
    }

    pub fn is_aligned(virtual_address: VirtualAddress, alignment: usize) bool {
        return common.is_aligned(virtual_address.value(), alignment);
    }

    pub fn format(virtual_address: VirtualAddress, comptime _: []const u8, _: common.InternalFormatOptions, writer: anytype) @TypeOf(writer).Error!void {
        try common.internal_format(writer, "0x{x}", .{virtual_address.value()});
    }
};

const common = @import("common");
const assert = common.assert;
const log = common.log.scoped(.Privileged);

// This package provides of privileged data structures and routines to both kernel and bootloaders, for now
// TODO: implement properly
//const crash = @import("privileged/crash.zig");
//pub const panic = crash.panic;
//pub const panic_extended = crash.panic_extended;

pub const arch = @import("privileged/arch.zig");
pub const Capabilities = @import("privileged/capabilities.zig");
pub const ELF = @import("privileged/elf.zig");
pub const Executable = @import("privileged/executable.zig");
pub const Heap = @import("privileged/heap.zig");
pub const MappingDatabase = @import("privileged/mapping_database.zig");
pub const UEFI = @import("privileged/uefi.zig");
pub const VirtualAddressSpace = @import("privileged/virtual_address_space.zig");
pub const scheduler_type = SchedulerType.round_robin;
pub const Scheduler = switch (scheduler_type) {
    .round_robin => @import("privileged/round_robin.zig"),
    else => @compileError("other scheduler is not supported right now"),
};

pub const ResourceOwner = enum(u2) {
    bootloader = 0,
    kernel = 1,
    user = 2,
};

pub const CoreSupervisorData = extern struct {
    is_valid: bool,
    next: ?*CoreSupervisorData,
    previous: ?*CoreSupervisorData,
    mdb_root: VirtualAddress(.local),
    init_rootcn: Capabilities.CTE,
    scheduler_state: Scheduler.State,
    kernel_offset: i64,
    irq_in_use: [arch.dispatch_count]u8, // bitmap of handed out caps
    irq_dispatch: [arch.dispatch_count]Capabilities.CTE,
    pending_ram_in_use: u8,
    pending_ram: [4]RAM,
};

const RAM = extern struct {
    base: u64,
    bytes: u64,
};

pub const RBED = struct {
    queue_head: ?*CoreDirectorData,
    queue_tail: ?*CoreDirectorData,
    // TODO: more stuff
};

pub const SchedulerType = enum(u8) {
    round_robin,
    rate_based_earliest_deadline,
};

pub const CoreDirectorData = extern struct {
    dispatcher_handle: VirtualAddress(.local),
    disabled: bool,
    cspace: CTE,
    vspace: usize,
    dispatcher_cte: CTE,
    faults_taken: u32,
    is_vm_guest: bool,
    // TODO: guest desc
    domain_id: u64,
    // TODO: wakeup time
    wakeup_previous: ?*CoreDirectorData,
    wakeup_next: ?*CoreDirectorData,
    next: ?*CoreDirectorData,
    previous: ?*CoreDirectorData,

    pub fn context_switch(core_director_data: *CoreDirectorData) void {
        arch.paging.context_switch(core_director_data.vspace);
        context_switch_counter += 1;
        log.warn("implement LDT", .{});
    }

    var context_switch_counter: usize = 0;
};

pub const CoreDirectorSharedGeneric = extern struct {
    disabled: u32,
    haswork: u32,
    udisp: VirtualAddress(.local),
    lmp_delivered: u32,
    lmp_seen: u32,
    lmp_hint: VirtualAddress(.local),
    dispatcher_run: VirtualAddress(.local),
    dispatcher_lrpc: VirtualAddress(.local),
    dispatcher_page_fault: VirtualAddress(.local),
    dispatcher_page_fault_disabled: VirtualAddress(.local),
    dispatcher_trap: VirtualAddress(.local),
    // TODO: time
    systime_frequency: u64,
    core_id: CoreId,

    pub fn get_disabled_save_area(core_director_shared_generic: *CoreDirectorSharedGeneric) *arch.Registers {
        const core_director_shared_arch = @fieldParentPtr(arch.CoreDirectorShared, "base", core_director_shared_generic);
        return &core_director_shared_arch.disabled_save_area;
    }
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
            return @intToEnum(PA, common.align_forward(usize, physical_address.value(), alignment));
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

        pub fn to_physical_address(virtual_address: VA) PhysicalAddress(locality) {
            assert(virtual_address.value() >= common.config.kernel_higher_half_address);
            const address = PhysicalAddress(locality).new(virtual_address.value() - common.config.kernel_higher_half_address);
            return address;
        }

        pub fn to_local(virtual_address: VA) VirtualAddress(.local) {
            comptime {
                assert(locality == .global);
            }
            return @intToEnum(VirtualAddress(.local), @enumToInt(virtual_address));
        }

        pub fn to_global(virtual_address: VA) VirtualAddress(.global) {
            comptime {
                assert(locality == .local);
            }
            return @intToEnum(VirtualAddress(.global), @enumToInt(virtual_address));
        }

        pub fn format(virtual_address: VA, comptime _: []const u8, _: common.InternalFormatOptions, writer: anytype) @TypeOf(writer).Error!void {
            try common.internal_format(writer, "0x{x}", .{virtual_address.value()});
        }
    };
}

pub fn PhysicalMemoryRegion(comptime locality: CoreLocality) type {
    return extern struct {
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

        pub fn offset(physical_memory_region: PMR, asked_offset: usize) PMR {
            assert(asked_offset < physical_memory_region.size);

            var result = physical_memory_region;
            result.address = result.address.offset(asked_offset);
            result.size -= asked_offset;
            return result;
        }

        pub fn add_offset(physical_memory_region: *PMR, asked_offset: usize) void {
            physical_memory_region.* = physical_memory_region.offset(asked_offset);
        }

        /// Result: chop, the rest is modified through the pointer
        pub fn chop(physical_memory_region: *PMR, asked_offset: usize) PMR {
            const ptr_result = physical_memory_region.offset(asked_offset);
            const result = PMR{
                .address = physical_memory_region.address,
                .size = physical_memory_region.size - ptr_result.size,
            };
            physical_memory_region.* = ptr_result;

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

        pub fn offset(virtual_memory_region: VMR, asked_offset: usize) VMR {
            assert(asked_offset < virtual_memory_region.size);

            var result = virtual_memory_region;
            result.address = result.address.offset(asked_offset);
            result.size -= asked_offset;
            return result;
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

pub const PhysicalAddressSpace = extern struct {
    free_list: List = .{},
    heap_list: List = .{},

    const AllocateError = error{
        not_base_page_aligned,
        out_of_memory,
    };

    const valid_page_sizes = common.arch.valid_page_sizes;

    pub fn allocate(physical_address_space: *PhysicalAddressSpace, size: u64, page_size: u64) AllocateError!PhysicalMemoryRegion(.local) {
        if (size >= valid_page_sizes[0]) {
            if (!common.is_aligned(size, valid_page_sizes[0])) {
                log.err("Size is 0x{x} but alignment should be at least 0x{x}", .{ size, valid_page_sizes[0] });
                return AllocateError.not_base_page_aligned;
            }

            var node_ptr = physical_address_space.free_list.first;

            const allocated_region = blk: {
                while (node_ptr) |node| : (node_ptr = node.next) {
                    const result_address = node.descriptor.address.aligned_forward(page_size);
                    const size_up = size + result_address.value() - node.descriptor.address.value();
                    if (node.descriptor.size > size_up) {
                        const allocated_region = PhysicalMemoryRegion(.local){
                            .address = result_address,
                            .size = size,
                        };
                        node.descriptor.address.add_offset(size_up);
                        node.descriptor.size -= size_up;

                        break :blk allocated_region;
                    } else if (node.descriptor.size == size_up) {
                        const allocated_region = node.descriptor.offset(size_up - size);
                        if (node.previous) |previous| previous.next = node.next;
                        if (node.next) |next| next.previous = node.previous;
                        if (node_ptr == physical_address_space.free_list.first) physical_address_space.free_list.first = node.next;
                        if (node_ptr == physical_address_space.free_list.last) physical_address_space.free_list.last = node.previous;

                        break :blk allocated_region;
                    }
                }

                return AllocateError.out_of_memory;
            };

            // For now, just zero it out.
            // TODO: in the future, better organization of physical memory to know for sure if the memory still obbeys the upcoming zero flag
            const region_bytes = allocated_region.to_higher_half_virtual_address().access_bytes();
            common.zero(region_bytes);

            return allocated_region;
        } else {
            if (physical_address_space.heap_list.last) |last| {
                if (last.descriptor.size >= size) {
                    const chop = last.descriptor.chop(size);
                    return chop;
                } else {
                    @panic("insufficient size");
                }
            } else {
                var heap_region = try physical_address_space.allocate(valid_page_sizes[1], valid_page_sizes[0]);
                const region_ptr = heap_region.chop(@sizeOf(Region)).address.to_higher_half_virtual_address().access(*Region);
                region_ptr.* = .{
                    .descriptor = heap_region,
                };
                physical_address_space.heap_list.append(region_ptr);

                return try physical_address_space.allocate(size, page_size);
            }
        }
    }

    pub fn free(physical_address_space: *PhysicalAddressSpace, size: u64) void {
        _ = physical_address_space;
        _ = size;

        @panic("todo free pages");
    }

    pub fn log_free_memory(physical_address_space: *PhysicalAddressSpace) void {
        var node_ptr = physical_address_space.free_list.first;
        var size: u64 = 0;
        while (node_ptr) |node| : (node_ptr = node.next) {
            size += node.descriptor.size;
        }

        log.debug("Free memory: {} bytes", .{size});
    }

    const List = extern struct {
        first: ?*Region = null,
        last: ?*Region = null,
        count: u64 = 0,

        pub fn append(list: *List, node: *Region) void {
            defer list.count += 1;
            if (list.last) |last| {
                last.next = node;
                node.previous = last;
                list.last = node;
            } else {
                list.first = node;
                list.last = node;
            }
        }

        pub fn remove(list: *List, node: *Region) void {
            if (list.first) |first| {
                if (first == node) {
                    list.first = node.next;
                }
            }

            if (list.last) |last| {
                if (last == node) {
                    list.last = node.previous;
                }
            }

            if (node.previous) |previous| {
                previous.next = node.next;
            }

            if (node.next) |next| {
                next.previous = node.previous;
            }
        }
    };

    pub const Region = extern struct {
        descriptor: PhysicalMemoryRegion(.local),
        previous: ?*Region = null,
        next: ?*Region = null,
    };
};

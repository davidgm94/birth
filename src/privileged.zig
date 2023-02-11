// This package provides of privileged data structures and routines to both kernel and bootloaders, for now

const lib = @import("lib.zig");
const assert = lib.assert;
const maxInt = lib.maxInt;
const Allocator = lib.Allocator;

pub const Address = @import("privileged/address.zig");
pub const arch = @import("privileged/arch.zig");
pub const Capabilities = @import("privileged/capabilities.zig");
pub const ELF = @import("privileged/elf.zig");
pub const Executable = @import("privileged/executable.zig");
pub const MappingDatabase = @import("privileged/mapping_database.zig");
pub const scheduler_type = SchedulerType.round_robin;
pub const Scheduler = switch (scheduler_type) {
    .round_robin => @import("privileged/round_robin.zig"),
    else => @compileError("other scheduler is not supported right now"),
};

pub const ACPI = @import("privileged/acpi.zig");

const bootloader = @import("bootloader");

pub const E9WriterError = error{};
pub const E9Writer = lib.Writer(void, E9WriterError, writeToE9);
pub const writer = E9Writer{ .context = {} };

fn writeToE9(_: void, bytes: []const u8) E9WriterError!usize {
    return arch.io.writeBytes(bytes);
}

pub const default_stack_size = 0x4000;

pub const ResourceOwner = enum(u2) {
    bootloader = 0,
    kernel = 1,
    user = 2,
};

pub const CoreSupervisorData = extern struct {
    is_valid: bool,
    next: ?*CoreSupervisorData,
    previous: ?*CoreSupervisorData,
    mdb_root: arch.VirtualAddress(.local),
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
    dispatcher_handle: arch.VirtualAddress(.local),
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

    pub fn contextSwitch(core_director_data: *CoreDirectorData) void {
        arch.paging.context_switch(core_director_data.vspace);
        context_switch_counter += 1;
        // TODO: implement LDT
    }

    var context_switch_counter: usize = 0;
};

pub const CoreDirectorSharedGeneric = extern struct {
    disabled: u32,
    haswork: u32,
    udisp: arch.VirtualAddress(.local),
    lmp_delivered: u32,
    lmp_seen: u32,
    lmp_hint: arch.VirtualAddress(.local),
    dispatcher_run: arch.VirtualAddress(.local),
    dispatcher_lrpc: arch.VirtualAddress(.local),
    dispatcher_page_fault: arch.VirtualAddress(.local),
    dispatcher_page_fault_disabled: arch.VirtualAddress(.local),
    dispatcher_trap: arch.VirtualAddress(.local),
    // TODO: time
    systime_frequency: u64,
    core_id: CoreId,

    pub fn getDisabledSaveArea(core_director_shared_generic: *CoreDirectorSharedGeneric) *arch.Registers {
        const core_director_shared_arch = @fieldParentPtr(arch.CoreDirectorShared, "base", core_director_shared_generic);
        return &core_director_shared_arch.disabled_save_area;
    }
};

pub const CoreLocality = enum {
    local,
    global,
};

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
    argument_page_address: arch.PhysicalAddress(.local) = .null,
};

const panic_logger = lib.log.scoped(.PANIC);

pub fn panic(comptime format: []const u8, arguments: anytype) noreturn {
    arch.disableInterrupts();
    panic_logger.err(format, arguments);
    arch.stopCPU();
}

pub fn zigPanic(message: []const u8, _: ?*lib.StackTrace, _: ?usize) noreturn {
    arch.disableInterrupts();
    panic("{s}", .{message});
}

pub fn dumpStackTrace(start_address: usize, frame_pointer: usize) void {
    _ = frame_pointer;
    _ = start_address;
    @panic("TODO: stack trace");
    // if (use_zig_stack_iterator) {
    //     var stack_iterator = common.StackIterator.init(start_address, frame_pointer);
    //     log.err("Stack trace:", .{});
    //     var stack_trace_i: u64 = 0;
    //     while (stack_iterator.next()) |return_address| : (stack_trace_i += 1) {
    //         if (return_address != 0) {
    //             log.err("{}: 0x{x}", .{ stack_trace_i, return_address });
    //         }
    //     }
    // } else {
    //     log.debug("============= STACK TRACE =============", .{});
    //     var ip = start_address;
    //     var stack_trace_depth: u64 = 0;
    //     var maybe_bp = @intToPtr(?[*]usize, frame_pointer);
    //     while (true) {
    //         defer stack_trace_depth += 1;
    //         if (ip != 0) log.debug("{}: 0x{x}", .{ stack_trace_depth, ip });
    //         if (maybe_bp) |bp| {
    //             ip = bp[1];
    //             maybe_bp = @intToPtr(?[*]usize, bp[0]);
    //         } else {
    //             break;
    //         }
    //     }
    //
    //     log.debug("============= STACK TRACE =============", .{});
    // }
}

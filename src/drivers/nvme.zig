const NVMe = @This();
// This has been implemented with NVMe Specification 2.0b

const kernel = @import("root");
const common = @import("../common.zig");
const context = @import("context");
const log = common.log.scoped(.NVMe);
const TODO = common.TODO;
const PhysicalAddress = common.PhysicalAddress;
const VirtualAddress = common.VirtualAddress;
const VirtualAddressSpace = common.VirtualAddressSpace;
const PhysicalMemoryRegion = common.PhysicalMemoryRegion;

const drivers = @import("../drivers.zig");
const Disk = drivers.Disk;
const PCI = drivers.PCI;
const DMA = drivers.DMA;

const Allocator = common.Allocator;

const x86_64 = common.arch.x86_64;

const Driver = NVMe;

pub var driver: *Driver = undefined;

device: *PCI.Device,
capabilities: CAP,
version: Version,
doorbell_stride: u64,
ready_transition_timeout: u64,
maximum_data_transfer_bytes: u64,
rtd3_entry_latency_us: u32,
maximum_data_outstanding_commands: u16,
model: [40]u8,

admin_submission_queue: [*]volatile u8,
admin_completion_queue: [*]volatile u8,
admin_completion_queue_head: u32,
admin_submission_queue_tail: u32,
admin_completion_queue_phase: bool,
admin_completion_queue_last_result: u32,
admin_completion_queue_last_status: u16,

io_submission_queue: ?[*]volatile u8,
io_completion_queue: ?[*]volatile u8,
io_completion_queue_head: u32,
io_submission_queue_tail: u32,
io_submission_queue_head: u32,
io_completion_queue_phase: bool,

prp_list_pages: [io_queue_entry_count]PhysicalAddress,
prp_list_virtual: VirtualAddress,

drives: []Drive,

const general_timeout = 5000;
const admin_queue_entry_count = 2;
const io_queue_entry_count = 256;
const submission_queue_entry_bytes = 64;
const completion_queue_entry_bytes = 16;
const Command = [16]u32;

const Drive = struct {
    disk: Disk,
    nsid: u32,

    pub const Initialization = struct {
        pub const Context = *NVMe.Drive;
        pub const Error = error{
            allocation_failure,
        };

        pub fn callback(allocator: Allocator, drive: *NVMe.Drive) Error!*Drive {
            _ = allocator;
            return drive;
        }
    };

    pub fn new(sector_size: u64, nsid: u32) Drive {
        return Drive{
            .disk = Disk{
                .type = .nvme,
                .sector_size = sector_size,
                .access = access,
                .get_dma_buffer = get_dma_buffer,
            },
            .nsid = nsid,
        };
    }

    pub fn access(disk: *Disk, special_context: u64, buffer: *DMA.Buffer, disk_work: Disk.Work) u64 {
        const virtual_address_space = @intToPtr(*VirtualAddressSpace, special_context);
        common.runtime_assert(@src(), buffer.completed_size == 0);
        common.runtime_assert(@src(), common.is_aligned(buffer.address.value, context.page_size));
        const drive = @fieldParentPtr(Drive, "disk", disk);
        const nvme = driver;
        log.debug("NVMe access", .{});
        log.debug("NVMe drive: {}", .{drive});
        log.debug("Buffer: (0x{x}, {})", .{ buffer.address.value, buffer.total_size });
        log.debug("Work: {}", .{disk_work});

        // Acquire lock
        // TODO: @Lock
        var completed_sector_count: u64 = 0;
        const total_sector_count = disk_work.sector_count;
        log.debug("NVMe byte size {s} request: {}", .{ @tagName(disk_work.operation), total_sector_count * disk.sector_size });
        // TODO: this assumes it's contiguous
        const base_physical_address = virtual_address_space.translate_address(buffer.address) orelse TODO(@src());
        while (completed_sector_count < total_sector_count) {
            const new_tail = (nvme.io_submission_queue_tail + 1) % io_queue_entry_count;
            const submission_queue_full = new_tail == @ptrCast(*volatile u32, &nvme.io_submission_queue_head).*;

            while (submission_queue_full) {
                // TODO: @Hack
                TODO(@src());
            }

            common.runtime_assert(@src(), context.page_size % disk.sector_size == 0);
            // TODO: fix this
            const request_sector_count = common.min(total_sector_count - completed_sector_count, (2 * context.page_size) / disk.sector_size);
            log.debug("Request sector index: {}. Work sector count: {}. Request sector count: {}", .{ completed_sector_count, total_sector_count, request_sector_count });
            const pointer_offset = completed_sector_count * disk.sector_size;
            const offset_physical_address = base_physical_address.offset(pointer_offset);
            const prps = [2]PhysicalAddress{ offset_physical_address, if ((request_sector_count * disk.sector_size) > context.page_size) offset_physical_address.offset(context.page_size) else PhysicalAddress.temporary_invalid() };

            var command = @ptrCast(*Command, @alignCast(@alignOf(Command), &nvme.io_submission_queue.?[nvme.io_submission_queue_tail * submission_queue_entry_bytes]));
            command[0] = (nvme.io_submission_queue_tail << 16) | @as(u32, if (disk_work.operation == .write) 0x01 else 0x02);
            // TODO:
            command[1] = drive.nsid;
            command[2] = 0;
            command[3] = 0;
            command[4] = 0;
            command[5] = 0;
            command[6] = @truncate(u32, prps[0].value);
            command[7] = @truncate(u32, prps[0].value >> 32);
            command[8] = @truncate(u32, prps[1].value);
            command[9] = @truncate(u32, prps[1].value >> 32);
            command[10] = @truncate(u32, disk_work.sector_offset + completed_sector_count);
            command[11] = @truncate(u32, (disk_work.sector_offset + completed_sector_count) >> 32);
            command[12] = @intCast(u16, request_sector_count - 1); // This is a 0's based value according to the spec, so it has to be decremented by one.
            command[13] = 0;
            command[14] = 0;
            command[15] = 0;

            nvme.io_submission_queue_tail = new_tail;
            @fence(.SeqCst);
            nvme.write_sqtdbl(1, new_tail);
            asm volatile ("hlt");

            completed_sector_count += request_sector_count;
        }
        // Release lock
        return disk_work.sector_count;
    }

    const Segment = struct {
        address: PhysicalAddress,
        size: u64,
    };

    pub fn get_dma_buffer(disk: *Disk, allocator: common.Allocator, sector_count: u64) common.Allocator.Error!DMA.Buffer {
        const sector_size = disk.sector_size;
        const byte_size = sector_count * sector_size;
        log.debug("Initializing search buffer", .{});
        return DMA.Buffer.new(allocator, .{ .size = common.align_forward(byte_size, context.page_size), .alignment = common.align_forward(sector_size, context.page_size) }) catch @panic("unable to initialize buffer");
    }
};

pub const Initialization = struct {
    pub const Context = *PCI;
    pub const Error = error{
        allocation_failure,
        not_found,
    };

    pub fn callback(virtual_address_space: *VirtualAddressSpace, pci: *PCI) Error!*Driver {
        const nvme_device = find(pci) orelse return Error.not_found;
        log.debug("Found controller", .{});
        driver = virtual_address_space.heap.allocator.create(Driver) catch return Error.allocation_failure;
        driver.* = NVMe.new(nvme_device);
        const result = driver.device.enable_features(PCI.Device.Features.from_flags(&.{ .interrupts, .busmastering_dma, .memory_space_access, .bar0 }), virtual_address_space);
        common.runtime_assert(@src(), result);
        log.debug("Device features enabled", .{});
        driver.init(virtual_address_space);

        log.debug("Driver initialized", .{});

        return driver;
    }
};

pub fn new(device: *PCI.Device) NVMe {
    return NVMe{
        .device = device,
        .capabilities = undefined,
        .version = undefined,
        .doorbell_stride = 0,
        .ready_transition_timeout = 0,
        .maximum_data_transfer_bytes = 0,
        .rtd3_entry_latency_us = 0,
        .maximum_data_outstanding_commands = 0,
        .model = undefined,
        .admin_submission_queue = undefined,
        .admin_completion_queue = undefined,
        .admin_submission_queue_tail = 0,
        .admin_completion_queue_head = 0,
        .admin_completion_queue_phase = false,
        .admin_completion_queue_last_result = 0,
        .admin_completion_queue_last_status = 0,
        .io_submission_queue = null,
        .io_completion_queue = null,
        .io_submission_queue_tail = 0,
        .io_completion_queue_head = 0,
        .io_submission_queue_head = 0,
        .io_completion_queue_phase = false,
        .prp_list_pages = undefined,
        .prp_list_virtual = undefined,
        .drives = &.{},
    };
}

pub fn find(pci: *PCI) ?*PCI.Device {
    return pci.find_device(0x1, 0x8);
}

inline fn read(nvme: *NVMe, comptime register: Property) register.type {
    return nvme.device.read_bar(register.type, 0, register.offset);
}

inline fn write(nvme: *NVMe, comptime register: Property, value: register.type) void {
    nvme.device.write_bar(register.type, 0, register.offset, value);
}

inline fn read_sqtdbl(nvme: *NVMe, index: u32) u32 {
    return nvme.device.read_bar(u32, 0, 0x1000 + nvme.doorbell_stride * (2 * index + 0));
}

inline fn read_cqhdbl(nvme: *NVMe, index: u32) u32 {
    return nvme.device.read_bar(u32, 0, 0x1000 + nvme.doorbell_stride * (2 * index + 1));
}

inline fn write_sqtdbl(nvme: *NVMe, index: u32, value: u32) void {
    nvme.device.write_bar(u32, 0, 0x1000 + nvme.doorbell_stride * (2 * index + 0), value);
}

inline fn write_cqhdbl(nvme: *NVMe, index: u32, value: u32) void {
    nvme.device.write_bar(u32, 0, 0x1000 + nvme.doorbell_stride * (2 * index + 1), value);
}

pub fn issue_admin_command(nvme: *NVMe, command: *Command, result: ?*u32) bool {
    @ptrCast(*Command, @alignCast(@alignOf(Command), &nvme.admin_submission_queue[nvme.admin_submission_queue_tail * @sizeOf(Command)])).* = command.*;
    nvme.admin_submission_queue_tail = (nvme.admin_submission_queue_tail + 1) % admin_queue_entry_count;

    // TODO: reset event
    @fence(.Release); // best memory barrier?
    common.runtime_assert(@src(), common.arch.are_interrupts_enabled());
    nvme.write_sqtdbl(0, nvme.admin_submission_queue_tail);
    asm volatile ("hlt");
    // TODO: wait for event
    //

    // This log makes a NVMe initialization bug disappear. We must evaluate it
    log.debug("NVMe admin completion queue last status: 0x{x}", .{nvme.admin_completion_queue_last_status});
    if (nvme.admin_completion_queue_last_status != 0) {
        const do_not_retry = nvme.admin_completion_queue_last_status & 0x8000 != 0;
        const more = nvme.admin_completion_queue_last_status & 0x4000 != 0;
        const command_retry_delay = @truncate(u8, nvme.admin_completion_queue_last_status >> 12) & 0x03;
        const status_code_type = @truncate(u8, nvme.admin_completion_queue_last_status >> 9) & 0x07;
        const status_code = @truncate(u8, nvme.admin_completion_queue_last_status >> 1);
        _ = do_not_retry;
        _ = more;
        _ = command_retry_delay;
        _ = status_code_type;
        _ = status_code;
        log.err("Admin command failed", .{});

        return false;
    }

    if (result) |p_result| p_result.* = nvme.admin_completion_queue_last_status;
    return true;
}

const PRPs = [2]PhysicalAddress;

pub fn init(nvme: *NVMe, virtual_address_space: *VirtualAddressSpace) void {
    nvme.capabilities = nvme.read(cap);
    nvme.version = nvme.read(vs);
    log.debug("Capabilities = {}. Version = {}", .{ nvme.capabilities, nvme.version });

    if (nvme.version.major != 1 and nvme.version.minor != 4) @panic("Version check failed");
    if (nvme.capabilities.mqes == 0) @panic("f3");
    if (!nvme.capabilities.css.nvm_command_set) @panic("f4");
    if (nvme.capabilities.mpsmin < context.page_shifter - 12) @panic("f5");
    if (nvme.capabilities.mpsmax < context.page_shifter - 12) @panic("f6");

    const previous_configuration = nvme.read(cc);
    log.debug("Previous configuration: {}", .{previous_configuration});

    if (previous_configuration.enable) {
        log.warn("The controller was enabled. Waiting for it to be ready before disabling", .{});
        while (!nvme.read(csts).ready) {}
        log.debug("Disabling the controller", .{});
        var config = nvme.read(cc);
        config.enable = false;
        nvme.write(cc, config);
        log.debug("Waiting for the controller to be ready", .{});
        while (nvme.read(csts).ready) {}
        log.debug("Controller disabled", .{});
    }

    nvme.doorbell_stride = @as(u64, 4) << nvme.capabilities.doorbell_stride;
    log.debug("NVMe doorbell stride: 0x{x}", .{nvme.doorbell_stride});

    nvme.ready_transition_timeout = nvme.capabilities.timeout * @as(u64, 500);
    log.debug("NVMe ready transition timeout: {} ms", .{nvme.ready_transition_timeout});

    nvme.write(cc, blk: {
        var cc_value = nvme.read(cc);
        log.debug("CC enable: {}", .{cc_value.enable});
        cc_value.css = .nvm_command_set;
        cc_value.mps = context.page_shifter - 12;
        cc_value.ams = .round_robin;
        cc_value.shn = .no_notification;
        cc_value.iosqes = 6;
        cc_value.iocqes = 4;
        break :blk cc_value;
    });

    {
        nvme.write(aqa, blk: {
            var aqa_value = nvme.read(aqa);
            aqa_value.asqs = admin_queue_entry_count - 1;
            aqa_value.acqs = admin_queue_entry_count - 1;
            break :blk aqa_value;
        });

        const admin_submission_queue_size = common.align_forward(admin_queue_entry_count * submission_queue_entry_bytes, context.page_size);
        const admin_completion_queue_size = common.align_forward(admin_queue_entry_count * completion_queue_entry_bytes, context.page_size);
        const admin_queue_data_structures_size = admin_submission_queue_size + admin_completion_queue_size;
        const admin_queue_allocation_slice = virtual_address_space.heap.allocator.allocBytes(@intCast(u29, context.page_size), admin_queue_data_structures_size, 0, 0) catch @panic("admin queue");
        const admin_queue_virtual_address = VirtualAddress.new(@ptrToInt(admin_queue_allocation_slice.ptr));
        const admin_queue_physical_address = virtual_address_space.translate_address(admin_queue_virtual_address) orelse @panic("admin queue data structure physical address");

        const admin_submission_queue_physical_address = admin_queue_physical_address;
        const admin_submission_queue_virtual_address = admin_queue_virtual_address;
        const admin_completion_queue_physical_address = admin_queue_physical_address.offset(admin_submission_queue_size);
        const admin_completion_queue_virtual_address = admin_queue_virtual_address.offset(admin_submission_queue_size);
        nvme.admin_submission_queue = admin_submission_queue_virtual_address.access([*]volatile u8);
        nvme.admin_completion_queue = admin_completion_queue_virtual_address.access([*]volatile u8);

        nvme.write(asq, ASQ{
            .reserved = 0,
            .asqb = @truncate(u52, admin_submission_queue_physical_address.value >> 12),
        });
        nvme.write(acq, ACQ{
            .reserved = 0,
            .acqb = @truncate(u52, admin_completion_queue_physical_address.value >> 12),
        });
    }

    nvme.write(cc, blk: {
        var new_cc = nvme.read(cc);
        new_cc.enable = true;
        break :blk new_cc;
    });

    {
        // TODO: HACK use a timeout
        while (true) {
            const status = nvme.read(csts);
            log.debug("Status: {}", .{status});
            if (status.cfs) {
                @panic("Fatal error when enabling the controller");
            } else if (status.ready) {
                break;
            }
        }
    }

    if (!nvme.device.enable_single_interrupt(virtual_address_space, x86_64.interrupts.HandlerInfo.new(nvme, handle_irq))) {
        @panic("f hanlder");
    }

    nvme.write(intmc, 1 << 0);

    // TODO: @Hack remove that 3 for a proper value
    const identify_data_allocation = virtual_address_space.heap.allocator.allocBytes(context.page_size, 3 * context.page_size, 0, 0) catch @panic("identity data");
    const identify_data_virtual_address = VirtualAddress.new(@ptrToInt(identify_data_allocation.ptr));
    const identify_data_physical_address = virtual_address_space.translate_address(identify_data_virtual_address) orelse @panic("identify data physical");
    const identify_data = identify_data_virtual_address.access([*]u8);

    {
        var command = common.zeroes(Command);
        command[0] = 0x06;
        command[6] = @truncate(u32, identify_data_physical_address.value);
        command[7] = @truncate(u32, identify_data_physical_address.value >> 32);
        command[10] = 0x01;

        if (!nvme.issue_admin_command(&command, null)) @panic("issue identify");

        nvme.maximum_data_transfer_bytes = blk: {
            if (identify_data[77] != 0) {
                // TODO: mpsmin? shouldnt this be mpsmax?
                break :blk @as(u64, 1) << (12 + @intCast(u6, identify_data[77]) + nvme.capabilities.mpsmin);
            } else {
                break :blk 0;
            }
        };

        nvme.rtd3_entry_latency_us = @ptrCast(*u32, @alignCast(@alignOf(u32), &identify_data[88])).*;
        nvme.maximum_data_outstanding_commands = @ptrCast(*u16, @alignCast(@alignOf(u16), &identify_data[514])).*;
        common.copy(u8, &nvme.model, identify_data[24 .. 24 + @sizeOf(@TypeOf(nvme.model))]);
        log.debug("NVMe model: {s}", .{nvme.model});

        if (nvme.rtd3_entry_latency_us > 250 * 1000) {
            nvme.rtd3_entry_latency_us = 250 * 1000;
        }

        if (identify_data[111] > 0x01) @panic("unsupported");

        if (nvme.maximum_data_transfer_bytes == 0 or nvme.maximum_data_transfer_bytes == 2097152) {
            nvme.maximum_data_transfer_bytes = 2097152;
        }
    }

    {
        var command = common.zeroes(Command);
        command[0] = 0x09;
        command[10] = 0x80;
        command[11] = 0;

        _ = nvme.issue_admin_command(&command, null);
    }

    {
        const queue_size = common.align_forward(io_queue_entry_count * completion_queue_entry_bytes, context.page_size);
        const queue_allocation = virtual_address_space.heap.allocator.allocBytes(context.page_size, queue_size, 0, 0) catch @panic("completion queue allocation");
        const queue_virtual_address = VirtualAddress.new(@ptrToInt(queue_allocation.ptr));
        const queue_physical_address = virtual_address_space.translate_address(queue_virtual_address) orelse @panic("completion queue physical");

        nvme.io_completion_queue = queue_virtual_address.access([*]u8);

        var command = common.zeroes(Command);
        command[0] = 0x05;
        command[6] = @truncate(u32, queue_physical_address.value);
        command[7] = @truncate(u32, queue_physical_address.value >> 32);
        command[10] = 1 | ((io_queue_entry_count - 1) << 16);
        command[11] = (1 << 0) | (1 << 1);

        if (!nvme.issue_admin_command(&command, null)) @panic("create queue");
    }

    {
        const queue_size = common.align_forward(io_queue_entry_count * submission_queue_entry_bytes, context.page_size);
        const queue_allocation = virtual_address_space.heap.allocator.allocBytes(context.page_size, queue_size, 0, 0) catch @panic("completion queue allocation");
        const queue_virtual_address = VirtualAddress.new(@ptrToInt(queue_allocation.ptr));
        const queue_physical_address = virtual_address_space.translate_address(queue_virtual_address) orelse @panic("submission queue physical");

        nvme.io_submission_queue = queue_virtual_address.access([*]u8);

        var command = common.zeroes(Command);
        command[0] = 0x01;
        command[6] = @truncate(u32, queue_physical_address.value);
        command[7] = @truncate(u32, queue_physical_address.value >> 32);
        command[10] = 1 | ((io_queue_entry_count - 1) << 16);
        command[11] = (1 << 0) | (1 << 16);

        if (!nvme.issue_admin_command(&command, null)) @panic("create queue");
    }

    {
        const prp_allocation = virtual_address_space.heap.allocator.allocBytes(context.page_size, nvme.prp_list_pages.len * context.page_size, 0, 0) catch @panic("prp list page");
        const prp_virtual_address = VirtualAddress.new(@ptrToInt(prp_allocation.ptr));
        const prp_base_physical_address = virtual_address_space.translate_address(prp_virtual_address) orelse @panic("prp");
        for (nvme.prp_list_pages) |*prp_list_page, page_i| {
            prp_list_page.* = prp_base_physical_address.offset(page_i * context.page_size);
        }

        virtual_address_space.map(nvme.prp_list_pages[0], nvme.prp_list_pages[0].to_higher_half_virtual_address(), .{ .write = true });
        nvme.prp_list_virtual = nvme.prp_list_pages[0].to_higher_half_virtual_address();
    }

    var nsid: u32 = 0;
    var drive_count: u64 = 0;
    var drives: [64]Drive = undefined;
    namespace: while (true) {
        {
            var command = common.zeroes(Command);
            command[0] = 0x06;
            command[1] = nsid;
            command[6] = @truncate(u32, identify_data_physical_address.value);
            command[7] = @truncate(u32, identify_data_physical_address.value >> 32);
            command[10] = 0x02;

            if (!nvme.issue_admin_command(&command, null)) @panic("identify");
        }

        var i: u64 = 0;
        while (i < 1024) : (i += 1) {
            nsid = @ptrCast(*align(1) u32, &identify_data[i]).*;
            if (nsid == 0) break :namespace;

            {
                var command = common.zeroes(Command);
                command[0] = 0x06;
                command[1] = nsid;
                command[6] = @truncate(u32, identify_data_physical_address.value + 0x1000);
                command[7] = @truncate(u32, (identify_data_physical_address.value + 0x1000) >> 32);
                command[10] = 0x00;

                if (!nvme.issue_admin_command(&command, null)) @panic("identify");
            }

            const formatted_lba_size = identify_data[0x1000 + 26];
            const lba_format = @ptrCast(*u32, @alignCast(@alignOf(u32), &identify_data[@as(u16, 0x1000) + 128 + 4 * @truncate(u4, formatted_lba_size)])).*;
            if (@truncate(u16, lba_format) != 0) continue;

            const sector_bytes_exponent = @truncate(u5, lba_format >> 16);
            if (sector_bytes_exponent < 9 or sector_bytes_exponent > 16) continue;
            const sector_size = @as(u64, 1) << sector_bytes_exponent;
            const drive = &drives[drive_count];
            drive_count += 1;
            common.runtime_assert(@src(), drive_count < drives.len);
            drive.* = Drive.new(sector_size, nsid);
            log.debug("New drive registered: {}", .{drive});
        }
    }

    nvme.drives = virtual_address_space.heap.allocator.alloc(Drive, drive_count) catch kernel.crash("unable to allocate for NVMe drives", .{});
    common.copy(Drive, nvme.drives, drives[0..drive_count]);
    for (nvme.drives) |*drive| {
        kernel.drivers.Driver(Disk, Drive).init(virtual_address_space.heap.allocator, drive) catch kernel.crash("Failed to initialized device", .{});
    }

    common.runtime_assert(@src(), drive_count == 1);
}

pub const Callback = fn (nvme: *NVMe, line: u64) bool;

pub fn handle_irq(nvme: *NVMe, line: u64) bool {
    _ = line;
    var from_admin = false;
    var from_io = false;

    if ((nvme.admin_completion_queue[nvme.admin_completion_queue_head * completion_queue_entry_bytes + 14] & (1 << 0) != 0) != nvme.admin_completion_queue_phase) {
        from_admin = true;
        nvme.admin_completion_queue_last_result = @ptrCast(*u32, @alignCast(@alignOf(u32), &nvme.admin_completion_queue[nvme.admin_completion_queue_head * completion_queue_entry_bytes + 0])).*;
        nvme.admin_completion_queue_last_status = (@ptrCast(*u16, @alignCast(@alignOf(u16), &nvme.admin_completion_queue[nvme.admin_completion_queue_head * completion_queue_entry_bytes + 14])).*) & 0xfffe;
        nvme.admin_completion_queue_head += 1;

        if (nvme.admin_completion_queue_head == admin_queue_entry_count) {
            nvme.admin_completion_queue_phase = !nvme.admin_completion_queue_phase;
            nvme.admin_completion_queue_head = 0;
        }

        nvme.write_cqhdbl(0, nvme.admin_completion_queue_head);

        // TODO: set event
    }

    while (nvme.io_completion_queue != null and ((nvme.io_completion_queue.?[nvme.io_completion_queue_head * completion_queue_entry_bytes + 14] & (1 << 0) != 0) != nvme.io_completion_queue_phase)) {
        from_io = true;

        const index = @ptrCast(*u16, @alignCast(@alignOf(u16), &nvme.io_completion_queue.?[nvme.io_completion_queue_head * completion_queue_entry_bytes + 12])).*;
        const status = (@ptrCast(*u16, @alignCast(@alignOf(u16), &nvme.io_completion_queue.?[nvme.io_completion_queue_head * completion_queue_entry_bytes + 14])).*) & 0xfffe;

        if (index < io_queue_entry_count) {
            if (status != 0) {
                const status_code_type = @truncate(u3, status >> 9);
                const status_code = @truncate(u8, status >> 1);

                // TODO: fix this @Hack (look at build.zig)
                common.panic(@src(), "NVMe driver internal error: {s}", .{get_error_message(status_code_type, status_code)});
            }
            // TODO: abstraction stuff
        } else @panic("NVMe wtf");

        @fence(.SeqCst);

        @ptrCast(*volatile u32, &nvme.io_submission_queue_head).* = @ptrCast(*u16, @alignCast(@alignOf(u16), &nvme.io_completion_queue.?[nvme.io_completion_queue_head * completion_queue_entry_bytes + 8])).*;
        // TODO: event set
        nvme.io_completion_queue_head += 1;

        if (nvme.io_completion_queue_head == io_queue_entry_count) {
            nvme.io_completion_queue_phase = !nvme.io_completion_queue_phase;
            nvme.io_completion_queue_head = 0;
        }

        nvme.write_cqhdbl(1, nvme.io_completion_queue_head);
    }

    return from_admin or from_io;
}

const generic_command_status_values = [_][]const u8{
    "Successful completion",
    "Invalid command opcode",
    "Invalid field in command",
    "Command ID conflict",
    "Data transfer error",
    "Commands aborted due to powerloss notification",
    "Internal error",
    "Command abort requested",
    "Command aborted due to SQ deletion",
    "Command aborted due to failed fused command",
    "Command aborted due to missing fused command",
    "Invalid namespace or format",
    "Command sequence error",
    "Invalid SGL segment descriptor",
    "Invalid number of SGL descriptors",
    "Data SGL length invalid",
    "Metadata SGL length invalid",
    "SGL descriptor type invalid",
    "Invalid use of controller memory buffer",
    "PRP offset invalid",
    "Atomic write unit exceeded",
    "Operation denied",
    "SGL offset invalid",
    "Reserved",
    "Host identifier inconsistent format",
    "Keep alive timer expired",
    "Keep alive timeout invalid",
    "Command aborted due to preempt and abort",
    "Sanitize failed",
    "Sanitize in progress",
    "SGL data block granularity invalid",
    "Command not supported for queue in CMB",
    "Namespace is write protected",
    "Command interrupted",
    "Transient transport error",
};

const generic_command_status_values_nvm = [_][]const u8{
    "LBA out of range",
    "Capacity exceeded",
    "Namespace not ready",
    "Reservation conflict",
    "Format in progress",
};

const command_specific_status_values = [_][]const u8{
    "Completion queue invalid",
    "Invalid queue identifier",
    "Invalid queue size",
    "Abort command limit exceeded",
    "Reserved",
    "Asynchronous event request limit exceeded",
    "Invalid firmware slot",
    "Invalid firmware image",
    "Invalid interrupt vector",
    "Invalid log page",
    "Invalid format",
    "Firmware activation requirse conventional reset",
    "Invalid queue deletion",
    "Feature identifier not saveable",
    "Feature not changeable",
    "Feature not namespace specific",
    "Firmware activation requires NVM subsystem reset",
    "Firmware activation requires controller level reset",
    "Firmware activation requires maximum time violation",
    "Firmware activation prohibited",
    "Overlapping range",
    "Namespace insufficient capacity",
    "Namespace identifier unavailable",
    "Reserved",
    "Namespace already attached",
    "Namespace is private",
    "Namespace not attached",
    "Thin provisioning not supported",
    "Controller list invalid",
    "Device self-test in progress",
    "Boot partition write prohibited",
    "Invalid controller identifier",
    "Invalid secondary controller state",
    "Invalid number of controller resources",
    "Invalid resource identifier",
    "Sanitize prohibited while persistent memory region is enabled",
    "ANA group identifier invalid",
    "ANA attach failed",
};

const command_specific_status_values_nvm = [_][]const u8{
    "Confliciting attributes",
    "Invalid protection information",
    "Attempted write to read only range",
};

const media_and_data_integrity_error_values_nvm = [_][]const u8{
    "Write fault",
    "Unrecovered read error",
    "End-to-end guard check error",
    "End-to-end application tag check error",
    "End-to-end reference tag check error",
    "Compare failure",
    "Access denied",
    "Dealocated or unwritten logical block",
};

const path_related_status_values = [_][]const u8{
    "Internal path error",
    "Asymmetric access persistent loss",
    "Asymmetric access inaccessible",
    "Asymmetric access transition",
};

fn get_error_message(status_code_type: u3, status_code: u8) []const u8 {
    log.debug("Status code type: 0x{x}. Status code: 0x{x}", .{ status_code_type, status_code });
    return switch (status_code_type) {
        0 => blk: {
            if (status_code < generic_command_status_values.len) {
                break :blk generic_command_status_values[status_code];
            } else if (status_code >= 0x80 and (status_code - 0x80) < generic_command_status_values_nvm.len) {
                break :blk generic_command_status_values_nvm[status_code - 0x80];
            } else {
                @panic("NVMe wtf 1");
            }
        },
        1 => blk: {
            if (status_code < command_specific_status_values.len) {
                break :blk command_specific_status_values[status_code];
            } else if (status_code >= 0x80 and (status_code - 0x80) < generic_command_status_values_nvm.len) {
                break :blk generic_command_status_values_nvm[status_code - 0x80];
            } else {
                @panic("NVMe wtf 2");
            }
        },
        2 => blk: {
            if (status_code >= 0x80 and (status_code - 0x80) < media_and_data_integrity_error_values_nvm.len) {
                break :blk media_and_data_integrity_error_values_nvm[status_code - 0x80];
            } else {
                @panic("NVMe wtf 3");
            }
        },
        3 => blk: {
            if (status_code >= 0x80 and (status_code - 0x80) < path_related_status_values.len) {
                break :blk path_related_status_values[status_code - 0x80];
            } else {
                @panic("NVMe wtf 4");
            }
        },
        else => "Unknown error",
    };
}

const DataTransfer = enum(u2) {
    no_data_transfer = 0,
    host_to_controller = 1,
    controller_to_host = 2,
    bidirectional = 3,
};

fn SubmissionQueueEntry(comptime Opcode: type) type {
    return packed struct {
        command_dword0: CommandDword0(Opcode),
    };
}

fn CommandDword0(comptime Opcode: type) type {
    return packed struct {
        opcode: Opcode,
        fuse: FUSE,
        reserved: u4,
        psdt: PSDT,
        cid: u16,

        const FUSE = enum(u2) {
            normal = 0,
            fuse_first_command = 1,
            fuse_second_command = 2,
            reserved = 3,
        };

        const PSDT = enum(u2) {
            prps_used = 0,
            sgls_buffer = 1,
            sgls_segment = 2,
            reserved = 3,
        };

        comptime {
            common.comptime_assert(@sizeOf(CommandDword0) == @sizeOf(u32));
        }
    };
}

const QueueType = enum(u2) {
    admin = 0,
    fabrics = 1,
    io = 2,

    const count = common.enum_values(QueueType).len;
};
const AdminOpcode = enum(u8) {
    delete_io_submission_queue = 0x00,
    create_io_submission_queue = 0x01,
    get_log_page = 0x02,
    delete_io_completion_queue = 0x04,
    create_io_completion_queue = 0x05,
    identify = 0x06,
    abort = 0x08,
    set_features = 0x09,
    get_features = 0x0a,
    asynchronous_event_request = 0x0c,
    namespace_management = 0x0d,
    firmware_commit = 0x10,
    firmware_image_download = 0x11,
    device_self_test = 0x14,
    namespace_attachment = 0x15,
    keep_alive = 0x18,
    directive_send = 0x19,
    directive_receive = 0x1a,
    virtualization_management = 0x1c,
    nvme_mi_send = 0x1d,
    nvme_mi_receive = 0x1e,
    capacity_management = 0x20,
    lockdown = 0x24,
    doorbell_buffer_config = 0x7c,
    fabrics_commands = 0x7f,
    format_nvm = 0x80,
    security_send = 0x81,
    security_receive = 0x82,
    sanitize = 0x84,
    get_lba_status = 0x86,

    pub inline fn is_generic_command(opcode: @This()) bool {
        return opcode & 0b10000000 != 0;
    }

    pub inline fn get_data_transfer(opcode: @This()) DataTransfer {
        return @intToEnum(DataTransfer, @truncate(u2, @enumToInt(opcode)));
    }

    pub inline fn get_function(opcode: @This()) u5 {
        return @truncate(u5, (@enumToInt(opcode) & 0b01111100) >> 2);
    }
};
const FabricsOpcode = enum(u8) {
    property_set = 0x00,
    connect = 0x01,
    property_get = 0x04,
    authentication_send = 0x05,
    authentication_receive = 0x06,
    disconnect = 0x08,
};

const IOOpcode = enum(u8) {
    flush = 0x00,
    reservation_register = 0x0d,
    reservation_report = 0x0e,
    reservation_acquire = 0x11,
    reservation_release = 0x15,

    _,
};

const opcodes = [QueueType.count]type{
    AdminOpcode,
    FabricsOpcode,
    IOOpcode,
};

const AdminCommonCommandFormat = packed struct {
    command_dword0: CommandDword0(AdminOpcode),
    nsid: u4,
    reserved: u8,
    // == Same as Common ==
    mptr: u8,
    dptr: u16,
    // == Same as Common ==
    ndt: u4,
    ndm: u4,
    command_dword12: u4,
    command_dword13: u4,
    command_dword14: u4,
    command_dword15: u4,

    comptime {
        common.comptime_assert(@sizeOf(AdminCommonCommandFormat) == @sizeOf(u64));
    }
};

const CommonCompletionQueueEntry = packed struct {
    dw0: u32,
    dw1: u32,
    dw2: DW2,

    const DW2 = packed struct {
        sqhp: u16,
        sqid: u16,

        comptime {
            common.comptime_assert(@sizeOf(DW2) == @sizeOf(u32));
        }
    };

    const DW3 = packed struct {
        cid: u16,
        phase_tag: bool,
        status_field: StatusField,

        comptime {
            common.comptime_assert(@sizeOf(DW3) == @sizeOf(u32));
        }
    };

    const StatusField = packed struct {
        sc: u8,
        sct: u3,
        crd: u2,
        more: bool,
        dnr: bool,
    };

    const GenericCommandStatus = enum(u8) {
        successful_completion = 0x00,
        invalid_command_opcode = 0x01,
        invalid_field_in_command = 0x02,
        command_id_conflict = 0x03,
        data_transfer_error = 0x04,
        commmands_aborted_due_to_power_loss_notification = 0x05,
        internal_error = 0x06,
        command_abort_requested = 0x07,
        command_aborted_due_to_sq_deletion = 0x08,
        command_aborted_due_to_failed_fused_command = 0x09,
        command_aborted_due_to_missing_fused_command = 0x0a,
        invalid_namespace_or_format = 0x0b,
        command_sequence_error = 0x0c,
        invalid_sgl_segment_descriptor = 0x0d,
        invalid_number_of_sgl_descriptors = 0x0e,
        data_sgl_length_invalid = 0x0f,
        metadata_sgl_length_invalid = 0x10,
        sgl_descriptor_type_invalid = 0x11,
        invalid_use_of_controller_memory_buffer = 0x12,
        prp_offset_invalid = 0x13,
        atomic_write_unit_exceeded = 0x14,
        operation_denied = 0x15,
        sgl_offset_invalid = 0x16,
        reserved = 0x17,
        host_identifier_inconsistent_format = 0x18,
        keep_alive_timer_expired = 0x19,
        keep_alive_timeout_invalid = 0x1a,
        command_aborted_due_to_preempt_and_abort = 0x1b,
        sanitize_failed = 0x1c,
        sanitize_in_progress = 0x1d,
        sgl_data_block_glanularity_invalid = 0x1e,
        command_not_supported_for_queue_in_cmb = 0x1f,
        namespace_is_write_protected = 0x20,
        command_interrupted = 0x21,
        transient_transport_error = 0x22,
        command_prohibited_by_command_and_feature_lockdown = 0x23,
        admin_command_media_not_ready = 0x24,
        lba_out_of_range = 0x80,
        capacity_exceeded = 0x81,
        namespace_not_ready = 0x82,
        reservation_conflict = 0x83,
        format_in_progress = 0x84,
        invalid_value_size = 0x85,
        invalid_key_size = 0x86,
        kv_key_does_not_exist = 0x87,
        unrecovered_error = 0x88,
        key_exists = 0x89,
        _,
    };

    const CommandSpecificStatus = enum(u8) {
        completion_queue_invalid = 0x00,
        invalid_queue_identifier = 0x01,
        invalid_queue_size = 0x02,
        abort_command_limit_exceeded = 0x03,
        reserved = 0x04,
        asynchronous_event_request_limi_exceeded = 0x05,
        invalid_firmware_slot = 0x06,
        invalid_firmware_image = 0x07,
        invalid_interrupt_vector = 0x08,
        invalid_log_page = 0x09,
        invalid_format = 0x0a,
        firmware_activation_requires_conventional_reset = 0x0b,
        invalid_queue_deletion = 0x0c,
        feature_identifier_not_saveable = 0x0d,
        feature_not_changeable = 0x0e,
        feature_not_namespace_specific = 0x0f,
        firmware_activation_requires_nvm_subsystem_reset = 0x10,
        firmware_activation_requires_controller_level_reset = 0x11,
        firmware_activation_requires_maximum_time_violation = 0x12,
        firmware_activation_prohibited = 0x13,
        overlapping_range = 0x14,
        namespace_insufficient_capacity = 0x15,
        namespace_identifier_unavailable = 0x16,
        reserved = 0x17,
        namespace_already_attached = 0x18,
        namespace_is_private = 0x19,
        namespace_not_attached = 0x1a,
        thin_provisioning_not_supported = 0x1b,
        controller_list_invalid = 0x1c,
        device_self_test_in_progress = 0x1d,
        boot_partition_write_prohibited = 0x1e,
        invalid_controller_identifier = 0x1f,
        invalid_secondary_controller_state = 0x20,
        invalid_number_of_controller_resources = 0x21,
        invalid_resource_identifier = 0x22,
        sanitize_prohibited_while_persistent_memory_region_is_enabled = 0x23,
        ana_group_identifier_invalid = 0x24,
        ana_attach_failed = 0x25,
        insufficient_capacity = 0x26,
        namespace_attachment_limit_exceeded = 0x27,
        prohibition_of_command_execution_not_supported = 0x28,
        io_command_set_not_supported = 0x29,
        io_command_set_not_enabled = 0x2a,
        io_command_set_combination_rejected = 0x2b,
        invalid_io_command_set = 0x2c,
        identifier_unavailable = 0x2d,
        _,
    };

    const IOCommandSpecificStatus = enum(u8) {
        conflicting_attributes = 0x80,
        invalid_protection_information = 0x81,
        attempted_write_to_read_only_range = 0x82,
        command_size_limit_exceeded = 0x83,
        zoned_boundary_error = 0xb8,
        zone_is_full = 0xb9,
        zone_is_read_only = 0xba,
        zone_is_offline = 0xbb,
        zone_invalid_write = 0xbc,
        too_many_active_zones = 0xbd,
        too_many_open_zones = 0xbe,
        invalid_zone_state_transition = 0xbf,
        _,
    };

    const FabricsCommandSpecificStatus = enum(u8) {
        incompatible_format = 0x80,
        controller_busy = 0x81,
        connect_invalid_parameters = 0x82,
        connected_restar_discovery = 0x83,
        connect_invalid_host = 0x84,
        invalid_queue_type = 0x85,
        discover_restart = 0x90,
        authentication_required = 0x91,
    };

    const MediaAndDataIntegrityError = enum(u8) {
        write_fault = 0x80,
        unrecovered_read_error = 0x81,
        end_to_end_guard_check_error = 0x82,
        end_to_end_application_tag_check_error = 0x83,
        end_to_end_reference_tag_check_error = 0x84,
        compare_failure = 0x85,
        access_denied = 0x86,
        deallocated_or_unwritten_logical_block = 0x87,
        end_to_end_storage_tag_check_error = 0x88,
    };

    const PathRelatedStatus = enum(u8) {
        internal_path_error = 0x00,
        asymmetric_access_persistent_loss = 0x01,
        asymmetric_access_inaccessible = 0x02,
        asymmetric_access_transition = 0x03,

        controller_pathing_error = 0x60,

        host_pathing_error = 0x70,
        command_aborted_by_host = 0x71,
    };
};

const Property = struct {
    offset: u64,
    type: type,
};

const cap = Property{ .offset = 0, .type = CAP };
const vs = Property{ .offset = 0x08, .type = Version };
const intms = Property{ .offset = 0xc, .type = u32 };
const intmc = Property{ .offset = 0x10, .type = u32 };
const cc = Property{ .offset = 0x14, .type = CC };
const csts = Property{ .offset = 0x1c, .type = CSTS };
const nssr = Property{ .offset = 0x20, .type = u32 };
const aqa = Property{ .offset = 0x24, .type = AQA };
const asq = Property{ .offset = 0x28, .type = ASQ };
const acq = Property{ .offset = 0x30, .type = ACQ };
const cmbloc = Property{ .offset = 0x38, .type = CMBLOC };
const cmbsz = Property{ .offset = 0x3c, .type = CMBSZ };
const bpinfo = Property{ .offset = 0x40, .type = BPINFO };
const bprsel = Property{ .offset = 0x44, .type = BPRSEL };
const bpmbl = Property{ .offset = 0x48, .type = BPMBL };
const cmbmsc = Property{ .offset = 0x50, .type = CMBMSC };
const cmbsts = Property{ .offset = 0x58, .type = CMBSTS };
const cmbebs = Property{ .offset = 0x5c, .type = CMBEBS };
const cmbswtp = Property{ .offset = 0x60, .type = CMBSWTP };
const nssd = Property{ .offset = 0x64, .type = u32 };
const crto = Property{ .offset = 0x68, .type = CRTO };
const pmrcap = Property{ .offset = 0xe00, .type = PMRCAP };
const pmrctl = Property{ .offset = 0xe04, .type = PMRCTL };
const pmrsts = Property{ .offset = 0xe08, .type = PMRSTS };
const pmrebs = Property{ .offset = 0xe0c, .type = PMREBS };
const pmrswtp = Property{ .offset = 0xe10, .type = PMRSWTP };
const pmrmscl = Property{ .offset = 0xe14, .type = PMRMSCL };
const pmrmscu = Property{ .offset = 0xe18, .type = u32 };

const CAP = packed struct {
    mqes: u16,
    cqr: bool,
    ams: u2,
    reserved: u5,
    timeout: u8,
    doorbell_stride: u4,
    nssrs: bool,
    css: CSS,
    bps: bool,
    cps: u2,
    mpsmin: u4,
    mpsmax: u4,
    pmrs: bool,
    cmbs: bool,
    nsss: bool,
    crwms: bool,
    crims: bool,
    reserved2: u3,

    const CSS = packed struct {
        nvm_command_set: bool,
        reserved: u5,
        io_command_sets: bool,
        no_io_command_set: bool,
    };

    comptime {
        common.comptime_assert(@sizeOf(CAP) == @sizeOf(u64));
        common.comptime_assert(@bitOffsetOf(CAP, "nssrs") == 36);
    }
};

const Version = packed struct {
    tertiary: u8,
    minor: u8,
    major: u16,
};

const CC = packed struct {
    enable: bool,
    reserved: u3,
    css: CSS,
    mps: u4,
    ams: AMS,
    shn: SHN,
    iosqes: u4,
    iocqes: u4,
    crime: bool,
    reserved2: u7,

    const CSS = enum(u3) {
        nvm_command_set = 0b000,
        all_supported_io_command_sets = 0b110,
        admin_command_set_only = 0b111,
        _,
    };

    const AMS = enum(u3) {
        round_robin = 0b000,
        weighted_round_robin_with_urgent_priority_class = 0b001,
        vendor_specific = 0b111,
        _,
    };

    const SHN = enum(u2) {
        no_notification = 0b00,
        normal_shutdown_notification = 0b01,
        abrupt_shutdown_notification = 0b10,
        reserved = 0b11,
    };

    comptime {
        common.comptime_assert(@sizeOf(CC) == @sizeOf(u32));
    }
};

const CSTS = packed struct {
    ready: bool,
    cfs: bool,
    shst: SHST,
    nssro: bool,
    pp: bool,
    st: bool,
    reserved: u25,

    const SHST = enum(u2) {
        norma_operation = 0,
        shutdown_processing_occurring = 1,
        shutdown_processing_complete = 2,
    };

    comptime {
        common.comptime_assert(@sizeOf(CSTS) == @sizeOf(u32));
    }
};

const AQA = packed struct {
    asqs: u12,
    reserved: u4,
    acqs: u12,
    reserved2: u4,

    comptime {
        common.comptime_assert(@sizeOf(AQA) == @sizeOf(u32));
    }
};

const ASQ = packed struct {
    reserved: u12,
    asqb: u52,

    comptime {
        common.comptime_assert(@sizeOf(ASQ) == @sizeOf(u64));
    }
};

const ACQ = packed struct {
    reserved: u12,
    acqb: u52,

    comptime {
        common.comptime_assert(@sizeOf(ACQ) == @sizeOf(u64));
    }
};

const CMBLOC = packed struct {
    bir: u3,
    cqmms: bool,
    cqpds: bool,
    cdpmls: bool,
    cdpcils: bool,
    cdmmms: bool,
    cqda: bool,
    reserved: u3,
    offset: u20,

    comptime {
        common.comptime_assert(@sizeOf(CMBLOC) == @sizeOf(u32));
    }
};

const CMBSZ = packed struct {
    sqs: bool,
    cqs: bool,
    lists: bool,
    rds: bool,
    wds: bool,
    reserved: u3,
    szu: SZU,
    size: u20,

    const SZU = enum(u4) {
        kib_4 = 0,
        kib_64 = 1,
        mib_1 = 2,
        mib_16 = 3,
        mib_256 = 4,
        gib_4 = 5,
        gib_64 = 6,
        _,
    };

    comptime {
        common.comptime_assert(@sizeOf(CMBSZ) == @sizeOf(u32));
    }
};

const BPINFO = packed struct {
    bpsz: u15,
    reserved: u9,
    brs: BRS,
    reserved: u5,
    abpid: bool,

    const BRS = enum(u2) {
        no_bpr = 0,
        bpr_in_progress = 1,
        bpr_completed = 2,
        bpr_error = 3,
    };

    comptime {
        common.comptime_assert(@sizeOf(BPINFO) == @sizeOf(u32));
    }
};

const BPRSEL = packed struct {
    bprsz: u10,
    bprof: u20,
    reserved: bool,
    bpid: bool,

    comptime {
        common.comptime_assert(@sizeOf(BPRSEL) == @sizeOf(u32));
    }
};

const BPMBL = packed struct {
    reserved: u12,
    bmbba: u52,

    comptime {
        common.comptime_assert(@sizeOf(BPMBL) == @sizeOf(u64));
    }
};

const CMBMSC = packed struct {
    cre: bool,
    cmse: bool,
    reserved: u10,
    cba: u52,

    comptime {
        common.comptime_assert(@sizeOf(CMBMSC) == @sizeOf(u64));
    }
};

const CMBSTS = packed struct {
    cbai: bool,
    reserved: u31,

    comptime {
        common.comptime_assert(@sizeOf(CMBSTS) == @sizeOf(u32));
    }
};

const CMBEBS = packed struct {
    cmbszu: CMBSZU,
    read_bypass_behavior: bool,
    reserved: u3,
    cmbwbz: u24,

    const CMBSZU = enum(u4) {
        bytes = 0,
        kib = 1,
        mib = 2,
        gib = 3,
        _,
    };

    comptime {
        common.comptime_assert(@sizeOf(CMBEBS) == @sizeOf(u32));
    }
};

const CMBSWTP = packed struct {
    cmbswtu: CMBSWTU,
    reserved: u4,
    cmbswtv: u24,

    const CMBSWTU = enum(u4) {
        bytes_s = 0,
        kibs_s = 1,
        mibs_s = 2,
        gibs_s = 3,
        _,
    };

    comptime {
        common.comptime_assert(@sizeOf(CMBSWTP) == @sizeOf(u32));
    }
};

const CRTO = packed struct {
    crwmt: u16,
    crimt: u16,

    comptime {
        common.comptime_assert(@sizeOf(CRTO) == @sizeOf(u32));
    }
};

const PMRCAP = packed struct {
    reserved: u3,
    rds: bool,
    wds: bool,
    bir: u3,
    pmrtu: PMRTU,
    pmrwbm: u4,
    reserved: u2,
    pmrto: u8,
    cmss: bool,
    reserved: u7,

    const PMRTU = enum(u2) {
        ms_500 = 0,
        minutes = 1,
        _,
    };

    comptime {
        common.comptime_assert(@sizeOf(PMRCAP) == @sizeOf(u32));
    }
};

const PMRCTL = packed struct {
    enable: bool,
    reserved: u31,

    comptime {
        common.comptime_assert(@sizeOf(PMRCTL) == @sizeOf(u32));
    }
};

const PMRSTS = packed struct {
    err: u8,
    nrdy: bool,
    hsts: HSTS,
    cbai: bool,
    reserved: u20,

    const HSTS = enum(u2) {
        normal = 0,
        restore_error = 1,
        read_only = 2,
        unreliable = 3,
    };

    comptime {
        common.comptime_assert(@sizeOf(PMRSTS) == @sizeOf(u32));
    }
};

const PMREBS = packed struct {
    pmrszu: PMRSZU,
    read_bypass_behavior: bool,
    reserved: u3,
    pmrwbz: u24,

    const PMRSZU = enum(u4) {
        bytes = 0,
        kib = 1,
        mib = 2,
        gib = 3,
        _,
    };
    comptime {
        common.comptime_assert(@sizeOf(PMREBS) == @sizeOf(u32));
    }
};

const PMRSWTP = packed struct {
    pmrswtu: PMRSWTU,
    reserved: u4,
    pmrswtv: u24,

    const PMRSWTU = enum(u4) {
        bytes_s = 0,
        kib_s = 1,
        mib_s = 2,
        gib_s,
        _,
    };

    comptime {
        common.comptime_assert(@sizeOf(PMRSWTP) == @sizeOf(u32));
    }
};

const PMRMSCL = packed struct {
    reserved: bool,
    cmse: bool,
    reserved2: u10,
    cba: u20,

    comptime {
        common.comptime_assert(@sizeOf(PMRMSCL) == @sizeOf(u32));
    }
};

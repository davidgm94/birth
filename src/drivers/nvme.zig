const kernel = @import("../kernel/kernel.zig");
const log = kernel.log.scoped(.NVMe);
const TODO = kernel.TODO;
const PCI = @import("pci.zig");

const x86_64 = @import("../kernel/arch/x86_64.zig");

const NVMe = @This();
pub var controller: NVMe = undefined;

device: *PCI.Device,
capabilities: u64,
version: u32,
doorbell_stride: u64,
ready_transition_timeout: u64,
maximum_data_transfer_bytes: u64,
rtd3_entry_latency_us: u32,
maximum_data_outstanding_commands: u16,
model: [40]u8,

admin_submission_queue: [*]u8,
admin_completion_queue: [*]u8,
admin_completion_queue_head: u32,
admin_submission_queue_tail: u32,
admin_completion_queue_phase: bool,
admin_completion_queue_last_result: u32,
admin_completion_queue_last_status: u16,

io_submission_queue: ?[*]u8,
io_completion_queue: ?[*]u8,
io_completion_queue_head: u32,
io_submission_queue_tail: u32,
io_completion_queue_phase: bool,

prp_list_pages: [io_queue_entry_count]kernel.Physical.Address,
prp_list_virtual: kernel.Virtual.Address,

const general_timeout = 5000;
const admin_queue_entry_count = 2;
const io_queue_entry_count = 256;
const submission_queue_entry_bytes = 64;
const completion_queue_entry_bytes = 16;
const Command = [16]u32;

pub fn new(device: *PCI.Device) NVMe {
    return NVMe{
        .device = device,
        .capabilities = 0,
        .version = 0,
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
        .io_completion_queue_phase = false,
        .prp_list_pages = undefined,
        .prp_list_virtual = undefined,
    };
}

pub fn find(pci: *PCI) ?*PCI.Device {
    return pci.find_device(0x1, 0x8);
}

const Error = error{
    not_found,
};

pub fn find_and_init(pci: *PCI) Error!void {
    const nvme_device = find(pci) orelse return Error.not_found;
    log.debug("Found NVMe drive", .{});
    controller = NVMe.new(nvme_device);
    const result = controller.device.enable_features(PCI.Device.Features.from_flags(&.{ .interrupts, .busmastering_dma, .memory_space_access, .bar0 }));
    kernel.assert(@src(), result);
    log.debug("Device features enabled", .{});

    controller.init();
}

const Register = struct {
    index: u64,
    offset: u64,
    type: type,
};

const cap = Register{ .index = 0, .offset = 0, .type = u64 };
const vs = Register{ .index = 0, .offset = 0x08, .type = u32 };
const intms = Register{ .index = 0, .offset = 0xc, .type = u32 };
const intmc = Register{ .index = 0, .offset = 0x10, .type = u32 };
const cc = Register{ .index = 0, .offset = 0x14, .type = u32 };
const csts = Register{ .index = 0, .offset = 0x1c, .type = u32 };
const aqa = Register{ .index = 0, .offset = 0x24, .type = u32 };
const asq = Register{ .index = 0, .offset = 0x28, .type = u64 };
const acq = Register{ .index = 0, .offset = 0x30, .type = u64 };

inline fn read(nvme: *NVMe, comptime register: Register) register.type {
    log.debug("Reading {} bytes from BAR register #{} at offset 0x{x})", .{ @sizeOf(register.type), register.index, register.offset });
    return nvme.device.read_bar(register.type, register.index, register.offset);
}

inline fn write(nvme: *NVMe, comptime register: Register, value: register.type) void {
    log.debug("Writing {} bytes (0x{x}) to BAR register #{} at offset 0x{x})", .{ @sizeOf(register.type), value, register.index, register.offset });
    nvme.device.write_bar(register.type, register.index, register.offset, value);
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
    _ = result;
    @ptrCast(*Command, @alignCast(@alignOf(Command), &nvme.admin_submission_queue[nvme.admin_submission_queue_tail * @sizeOf(Command)])).* = command.*;
    nvme.admin_submission_queue_tail = (nvme.admin_submission_queue_tail + 1) % admin_queue_entry_count;

    // TODO: reset event
    @fence(.SeqCst); // best memory barrier?
    kernel.assert(@src(), kernel.arch.are_interrupts_enabled());
    log.debug("Entering in a wait state", .{});
    nvme.write_sqtdbl(0, nvme.admin_submission_queue_tail);
    asm volatile ("hlt");
    // TODO: wait for event
    //

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
        log.debug("Admin command failed", .{});

        return false;
    }

    if (result) |p_result| p_result.* = nvme.admin_completion_queue_last_status;
    return true;
}

//inline fn read_SQTDBL(device: *PCIDevicei)     pci-> ReadBAR32(0, 0x1000 + doorbellStride * (2 * (i) + 0))    // Submission queue tail doorbell.
//inline fn write_SQTDBL(device: *PCIDevicei, x)  pci->WriteBAR32(0, 0x1000 + doorbellStride * (2 * (i) + 0), x)
//inline fn read_CQHDBL(device: *PCIDevicei)     pci-> ReadBAR32(0, 0x1000 + doorbellStride * (2 * (i) + 1))    // Completion queue head doorbell.
//inline fn write_CQHDBL(device: *PCIDevicei, x)  pci->WriteBAR32(0, 0x1000 + doorbellStride * (2 * (i) + 1), x)

pub fn init(nvme: *NVMe) void {
    nvme.capabilities = nvme.read(cap);
    nvme.version = nvme.read(vs);
    log.debug("Capabilities = 0x{x}. Version = {}", .{ nvme.capabilities, nvme.version });

    if ((nvme.version >> 16) < 1) @panic("f1");
    if ((nvme.version >> 16) == 1 and @truncate(u8, nvme.version >> 8) < 1) @panic("f2");
    if (@truncate(u16, nvme.capabilities) == 0) @panic("f3");
    if (~nvme.capabilities & (1 << 37) != 0) @panic("f4");
    if (@truncate(u4, nvme.capabilities >> 48) < kernel.arch.page_shifter - 12) @panic("f5");
    if (@truncate(u4, nvme.capabilities >> 52) < kernel.arch.page_shifter - 12) @panic("f6");

    nvme.doorbell_stride = @as(u64, 4) << @truncate(u4, nvme.capabilities >> 32);
    log.debug("NVMe doorbell stride: 0x{x}", .{nvme.doorbell_stride});

    nvme.ready_transition_timeout = @truncate(u8, nvme.capabilities >> 24) * @as(u64, 500);
    log.debug("NVMe ready transition timeout: 0x{x}", .{nvme.ready_transition_timeout});

    const previous_configuration = nvme.read(cc);
    log.debug("Previous configuration: 0x{x}", .{previous_configuration});

    log.debug("we are here", .{});
    if (previous_configuration & (1 << 0) != 0) {
        log.debug("branch", .{});
        // TODO. HACK we should use a timeout here
        while (~nvme.read(csts) & (1 << 0) != 0) {
            log.debug("busy waiting", .{});
        }
        nvme.write(cc, nvme.read(cc) & ~@as(cc.type, 1 << 0));
    }

    {
        // TODO. HACK we should use a timeout here
        while (nvme.read(csts) & (1 << 0) != 0) {}
        log.debug("past the timeout", .{});
    }

    nvme.write(cc, (nvme.read(cc) & 0xff00000f) | (0x00460000) | ((kernel.arch.page_shifter - 12) << 7));
    nvme.write(aqa, (nvme.read(aqa) & 0xF000F000) | ((admin_queue_entry_count - 1) << 16) | (admin_queue_entry_count - 1));

    const admin_submission_queue_size = admin_queue_entry_count * submission_queue_entry_bytes;
    const admin_completion_queue_size = admin_queue_entry_count * completion_queue_entry_bytes;
    const admin_queue_page_count = kernel.align_forward(admin_submission_queue_size, kernel.arch.page_size) + kernel.align_forward(admin_completion_queue_size, kernel.arch.page_size);
    const admin_queue_physical_address = kernel.Physical.Memory.allocate_pages(admin_queue_page_count) orelse @panic("admin queue");
    const admin_submission_queue_physical_address = admin_queue_physical_address;
    const admin_completion_queue_physical_address = admin_queue_physical_address.offset(kernel.align_forward(admin_submission_queue_size, kernel.arch.page_size));

    nvme.write(asq, admin_submission_queue_physical_address.value);
    nvme.write(acq, admin_completion_queue_physical_address.value);

    const admin_submission_queue_virtual_address = admin_submission_queue_physical_address.to_higher_half_virtual_address();
    const admin_completion_queue_virtual_address = admin_completion_queue_physical_address.to_higher_half_virtual_address();
    kernel.address_space.map(admin_submission_queue_physical_address, admin_submission_queue_virtual_address, kernel.Virtual.AddressSpace.Flags.from_flags(&.{.read_write}));
    kernel.address_space.map(admin_completion_queue_physical_address, admin_completion_queue_virtual_address, kernel.Virtual.AddressSpace.Flags.from_flags(&.{.read_write}));

    nvme.admin_submission_queue = admin_submission_queue_virtual_address.access([*]u8);
    nvme.admin_completion_queue = admin_completion_queue_virtual_address.access([*]u8);

    nvme.write(cc, nvme.read(cc) | (1 << 0));

    {
        // TODO: HACK use a timeout
        while (true) {
            const status = nvme.read(csts);
            if (status & (1 << 1) != 0) @panic("f") else if (status & (1 << 0) != 0) break;
        }
    }

    if (!nvme.device.enable_single_interrupt(x86_64.interrupts.HandlerInfo.new(nvme, handle_irq))) {
        @panic("f hanlder");
    }

    nvme.write(intmc, 1 << 0);

    // TODO: @Hack remove that 3 for a proper value
    const identify_data_physical_address = kernel.Physical.Memory.allocate_pages(3) orelse @panic("identify");
    const identify_data_virtual_address = identify_data_physical_address.to_higher_half_virtual_address();
    kernel.address_space.map(identify_data_physical_address, identify_data_virtual_address, kernel.Virtual.AddressSpace.Flags.from_flag(.read_write));
    const identify_data = identify_data_virtual_address.access([*]u8);

    {
        var command = kernel.zeroes(Command);
        command[0] = 0x06;
        command[6] = @truncate(u32, identify_data_physical_address.value);
        command[7] = @truncate(u32, identify_data_physical_address.value >> 32);
        command[10] = 0x01;

        if (!nvme.issue_admin_command(&command, null)) @panic("issue identify");

        nvme.maximum_data_transfer_bytes = if (identify_data[77] != 0) (@as(u64, 1) << (12 + @intCast(u6, identify_data[77]) + @truncate(u4, nvme.capabilities))) else 0;
        nvme.rtd3_entry_latency_us = @ptrCast(*u32, @alignCast(@alignOf(u32), &identify_data[88])).*;
        nvme.maximum_data_outstanding_commands = @ptrCast(*u16, @alignCast(@alignOf(u16), &identify_data[514])).*;
        kernel.copy(u8, &nvme.model, identify_data[24 .. 24 + @sizeOf(@TypeOf(nvme.model))]);
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
        var command = kernel.zeroes(Command);
        command[0] = 0x09;
        command[10] = 0x80;
        command[11] = 0;

        _ = nvme.issue_admin_command(&command, null);
    }

    {
        const size = kernel.align_forward(io_queue_entry_count * completion_queue_entry_bytes, kernel.arch.page_size);
        const page_count = kernel.bytes_to_pages(size, true);
        const queue_physical_address = kernel.Physical.Memory.allocate_pages(page_count) orelse @panic("ph comp");

        const physical_region = kernel.Physical.Memory.Region.new(queue_physical_address, size);
        physical_region.map(&kernel.address_space, queue_physical_address.to_higher_half_virtual_address(), kernel.Virtual.AddressSpace.Flags.from_flag(.read_write));
        nvme.io_completion_queue = queue_physical_address.to_higher_half_virtual_address().access([*]u8);

        var command = kernel.zeroes(Command);
        command[0] = 0x05;
        command[6] = @truncate(u32, queue_physical_address.value);
        command[7] = @truncate(u32, queue_physical_address.value >> 32);
        command[10] = 1 | ((io_queue_entry_count - 1) << 16);
        command[11] = (1 << 0) | (1 << 1);

        if (!nvme.issue_admin_command(&command, null)) @panic("create queue");
    }

    {
        const size = kernel.align_forward(io_queue_entry_count * submission_queue_entry_bytes, kernel.arch.page_size);
        const page_count = kernel.bytes_to_pages(size, true);
        const queue_physical_address = kernel.Physical.Memory.allocate_pages(page_count) orelse @panic("ph comp");

        const physical_region = kernel.Physical.Memory.Region.new(queue_physical_address, size);
        physical_region.map(&kernel.address_space, queue_physical_address.to_higher_half_virtual_address(), kernel.Virtual.AddressSpace.Flags.from_flag(.read_write));
        nvme.io_submission_queue = queue_physical_address.to_higher_half_virtual_address().access([*]u8);

        var command = kernel.zeroes(Command);
        command[0] = 0x01;
        command[6] = @truncate(u32, queue_physical_address.value);
        command[7] = @truncate(u32, queue_physical_address.value >> 32);
        command[10] = 1 | ((io_queue_entry_count - 1) << 16);
        command[11] = (1 << 0) | (1 << 16);

        if (!nvme.issue_admin_command(&command, null)) @panic("create queue");
    }

    {
        for (nvme.prp_list_pages) |*prp_list_page| {
            prp_list_page.* = kernel.Physical.Memory.allocate_pages(1) orelse @panic("prp physical");
        }

        kernel.address_space.map(nvme.prp_list_pages[0], nvme.prp_list_pages[0].to_higher_half_virtual_address(), kernel.Virtual.AddressSpace.Flags.from_flag(.read_write));
        nvme.prp_list_virtual = nvme.prp_list_pages[0].to_higher_half_virtual_address();
    }

    var nsid: u32 = 0;
    var device_count: u64 = 0;
    namespace: while (true) {
        {
            var command = kernel.zeroes(Command);
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
            log.debug("nsid", .{});

            {
                var command = kernel.zeroes(Command);
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
            log.debug("lba_format", .{});

            const sector_bytes_exponent = @truncate(u5, lba_format >> 16);
            if (sector_bytes_exponent < 9 or sector_bytes_exponent > 16) continue;
            const sector_bytes = @as(u64, 1) << sector_bytes_exponent;
            log.debug("sector bytes: {}", .{sector_bytes});

            device_count += 1;
        }
    }

    log.debug("Device count: {}", .{device_count});
    TODO(@src());
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
            if (status != 0) {} else {}
            TODO(@src());
        } else @panic("wtf");
    }

    return from_admin or from_io;
}

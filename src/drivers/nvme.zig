const kernel = @import("../kernel/kernel.zig");
const log = kernel.log.scoped(.NVMe);
const TODO = kernel.TODO;
const PCIController = @import("pci.zig");
const PCIDevice = @import("pci_device.zig");

const NVMe = @This();
pub var controller: NVMe = undefined;

device: *PCIDevice,
capabilities: u64,
version: u32,
doorbell_stride: u64,
ready_transition_timeout: u64,
admin_submission_queue: [*]u8,
admin_completion_queue: [*]u8,

const general_timeout = 5000;
const admin_queue_entry_count = 2;
const io_queue_entry_count = 256;
const submission_queue_entry_bytes = 64;
const completion_queue_entry_bytes = 16;

pub fn new(device: *PCIDevice) NVMe {
    return NVMe{
        .device = device,
        .capabilities = 0,
        .version = 0,
        .doorbell_stride = 0,
        .ready_transition_timeout = 0,
        .admin_submission_queue = undefined,
        .admin_completion_queue = undefined,
    };
}

pub fn find(pci: *PCIController) ?*PCIDevice {
    return pci.find_device(0x1, 0x8);
}

const Error = error{
    not_found,
};

pub fn find_and_init(pci: *PCIController) Error!void {
    const nvme_device = find(pci) orelse return Error.not_found;
    log.debug("Found NVMe drive", .{});
    controller = NVMe.new(nvme_device);
    const result = controller.device.enable_features(PCIDevice.Features.from_flags(&.{ .interrupts, .busmastering_dma, .memory_space_access, .bar0 }));
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

    TODO(@src());
}

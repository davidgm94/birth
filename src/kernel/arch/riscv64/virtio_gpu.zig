const kernel = @import("../../kernel.zig");
const virtio = @import("virtio.zig");
const MMIO = virtio.MMIO;
const SplitQueue = virtio.SplitQueue;
const Descriptor = virtio.Descriptor;

const Graphics = kernel.graphics;
const log = kernel.log.scoped(.VirtioGPU);
const TODO = kernel.TODO;

const GenericDriver = kernel.driver;

const Driver = @This();

graphics: Graphics,
// TODO: organize this mess
mmio: *volatile MMIO,
control_queue: *volatile SplitQueue,
cursor_queue: *volatile SplitQueue,
display_info: ResponseDisplayInfo,
pmode: ResponseDisplayInfo.Display,
initialized: bool,
received_display_info: bool,
transfered: bool,
flushed: bool,

pub const Initialization = struct {
    pub const Context = u64;
    pub const Error = error{
        allocation_failure,
    };

    pub fn callback(allocate: GenericDriver.AllocationCallback, mmio_address: Context) Error!*Driver {
        kernel.arch.Virtual.map(mmio_address, 1);
        const driver_allocation = allocate(@sizeOf(Driver)) orelse return Error.allocation_failure;
        const driver = @intToPtr(*Driver, driver_allocation);
        driver.graphics.type = .virtio;
        // Have to manually set the initialization driver here to get it from the interrupt
        initialization_driver = driver;
        driver.mmio = @intToPtr(*volatile MMIO, mmio_address);
        driver.mmio.init();

        driver.control_queue = driver.mmio.add_queue_to_device(0);
        driver.cursor_queue = driver.mmio.add_queue_to_device(1);

        // TODO: stop hardcoding interrupt number
        kernel.arch.Interrupts.register_external_interrupt_handler(7, handler);
        driver.mmio.set_driver_initialized();

        var header = kernel.zeroes(ControlHeader);
        header.type = ControlType.cmd_get_display_info;
        driver.operate(kernel.as_bytes(&header), @sizeOf(ResponseDisplayInfo));
        while (!driver.received_display_info) {
            kernel.spinloop_hint();
        }

        if (driver.display_info.header.type != ControlType.resp_ok_display_info) {
            @panic("display info corrupted");
        }

        log.debug("Display info", .{});
        for (driver.display_info.pmodes) |pmode_it, i| {
            if (pmode_it.enabled != 0) log.debug("[{}] pmode: {}", .{ i, pmode_it });
        }
        driver.pmode = driver.display_info.pmodes[0];

        var create = kernel.zeroes(ResourceCreate2D);
        create.header.type = ControlType.cmd_resource_create_2d;
        create.format = Format.R8G8B8A8_UNORM;
        create.resource_id = 1;
        create.width = driver.pmode.rect.width;
        create.height = driver.pmode.rect.height;

        driver.operate(kernel.as_bytes(&create), @sizeOf(ControlHeader));

        const framebuffer_pixel_count = driver.pmode.rect.width * driver.pmode.rect.height;
        const framebuffer_size = @sizeOf(u32) * framebuffer_pixel_count;
        const framebuffer_allocation = kernel.heap.allocate(framebuffer_size, true, true) orelse @panic("unable to allocate framebuffer");

        driver.graphics.framebuffer = Graphics.Framebuffer{
            .buffer = @intToPtr([*]u32, framebuffer_allocation.virtual),
            .width = driver.pmode.rect.width,
            .height = driver.pmode.rect.height,
            .cursor = Graphics.Point{ .x = 0, .y = 0 },
        };

        const backing_size = @sizeOf(ResourceAttachBacking) + @sizeOf(MemoryEntry);

        const backing_allocation = kernel.heap.allocate(backing_size, true, true) orelse @panic("unable to allocate backing");
        const backing = @intToPtr(*volatile ResourceAttachBacking, backing_allocation.virtual);
        backing.* = ResourceAttachBacking{
            .header = ControlHeader{
                .type = ControlType.cmd_resource_attach_backing,
                .flags = 0,
                .fence_id = 0,
                .context_id = 0,
                .padding = 0,
            },
            .resource_id = 1,
            .entry_count = 1,
        };
        backing.set_entry(0, MemoryEntry{
            .address = framebuffer_allocation.physical,
            .length = framebuffer_size,
            .padding = 0,
        });

        // TODO: fix double allocation
        driver.operate(@intToPtr([*]u8, backing_allocation.virtual)[0..backing_size], @sizeOf(ControlHeader));

        var set_scanout = kernel.zeroes(SetScanout);
        set_scanout.header.type = ControlType.cmd_set_scanout;
        set_scanout.rect = driver.pmode.rect;
        set_scanout.resource_id = 1;

        driver.operate(kernel.as_bytes(&set_scanout), @sizeOf(ControlHeader));

        const framebuffer = @intToPtr([*]u32, framebuffer_allocation.virtual)[0..framebuffer_pixel_count];
        for (framebuffer) |*pixel| {
            pixel.* = 0xffffffff;
        }

        driver.send_and_flush_framebuffer();

        log.debug("GPU driver initialized", .{});

        return driver;
    }
};

const ControlType = enum(u32) {
    // 2D
    cmd_get_display_info = 0x0100,
    cmd_resource_create_2d,
    cmd_resource_unref,
    cmd_set_scanout,
    cmd_resource_flush,
    cmd_transfer_to_host_2d,
    cmd_resource_attach_backing,
    cmd_resource_detach_backing,
    cmd_get_capset_info,
    cmd_get_capset,
    cmd_get_edid,

    // cursor
    cmd_update_cursor = 0x0300,
    cmd_move_cursor,

    // success responses
    resp_ok_nodata = 0x1100,
    resp_ok_display_info,
    resp_ok_capset_info,
    resp_ok_capset,
    resp_ok_edid,

    // error responses
    resp_err_unspec = 0x1200,
    resp_err_out_of_memory,
    resp_err_invalid_scanout_id,
    resp_err_invalid_resource_id,
    resp_err_invalid_context_id,
    resp_err_invalid_parameter,
};

const Flag = enum(u32) {
    fence = 1 << 0,
};

const ControlHeader = struct {
    type: ControlType,
    flags: u32,
    fence_id: u64,
    context_id: u32,
    padding: u32,
};

const max_scanouts = 16;

const Rect = struct {
    x: u32,
    y: u32,
    width: u32,
    height: u32,
};

const ResponseDisplayInfo = struct {
    header: ControlHeader,
    pmodes: [max_scanouts]Display,

    const Display = struct {
        rect: Rect,
        enabled: u32,
        flags: u32,
    };
};

const Format = enum(u32) {
    B8G8R8A8_UNORM = 1,
    B8G8R8X8_UNORM = 2,
    A8R8G8B8_UNORM = 3,
    X8R8G8B8_UNORM = 4,

    R8G8B8A8_UNORM = 67,
    X8B8G8R8_UNORM = 68,

    A8B8G8R8_UNORM = 121,
    R8G8B8X8_UNORM = 134,
};

const ResourceCreate2D = struct {
    header: ControlHeader,
    resource_id: u32,
    format: Format,
    width: u32,
    height: u32,
};

const MemoryEntry = struct {
    address: u64,
    length: u32,
    padding: u32,
};

const ResourceAttachBacking = struct {
    header: ControlHeader,
    resource_id: u32,
    entry_count: u32,
    // TODO: variable-length array afterwards

    inline fn set_entry(self: *volatile @This(), index: u64, entry: MemoryEntry) void {
        const entry_ptr = @intToPtr(*MemoryEntry, @ptrToInt(self) + @sizeOf(@This()) + (@sizeOf(MemoryEntry) * index));
        entry_ptr.* = entry;
    }
};

const SetScanout = struct {
    header: ControlHeader,
    rect: Rect,
    scanout_id: u32,
    resource_id: u32,
};

const TransferControlToHost2D = struct {
    header: ControlHeader,
    rect: Rect,
    offset: u64,
    resource_id: u32,
    padding: u32,
};

const ResourceFlush = struct {
    header: ControlHeader,
    rect: Rect,
    resource_id: u32,
    padding: u32,
};

pub fn send_and_flush_framebuffer(driver: *Driver) void {
    var transfer_to_host = kernel.zeroes(TransferControlToHost2D);
    transfer_to_host.header.type = ControlType.cmd_transfer_to_host_2d;
    transfer_to_host.rect = driver.pmode.rect;
    transfer_to_host.resource_id = 1;

    log.debug("Sending transfer", .{});
    driver.transfered = false;
    driver.operate(kernel.as_bytes(&transfer_to_host), @sizeOf(ControlHeader));
    while (!driver.transfered) {
        kernel.spinloop_hint();
    }

    var flush = kernel.zeroes(ResourceFlush);
    flush.header.type = ControlType.cmd_resource_flush;
    flush.rect = driver.pmode.rect;
    flush.resource_id = 1;

    log.debug("Sending flush", .{});
    driver.flushed = false;
    driver.operate(kernel.as_bytes(&flush), @sizeOf(ControlHeader));
    while (!driver.flushed) {
        kernel.spinloop_hint();
    }
    kernel.assert(@src(), driver.transfered);
    kernel.assert(@src(), driver.flushed);
}

pub fn operate(driver: *Driver, request_bytes: []const u8, response_size: u32) void {
    const request = kernel.heap.allocate(request_bytes.len, true, true) orelse @panic("unable to allocate memory for gpu request");
    kernel.copy(u8, @intToPtr([*]u8, request.virtual)[0..request_bytes.len], request_bytes);

    var descriptor1: u16 = 0;
    var descriptor2: u16 = 0;

    driver.control_queue.push_descriptor(&descriptor2).* = Descriptor{
        .address = (kernel.heap.allocate(response_size, true, true) orelse @panic("unable to get memory for gpu response")).physical,
        .flags = @enumToInt(Descriptor.Flag.write_only),
        .length = response_size,
        .next = 0,
    };

    driver.control_queue.push_descriptor(&descriptor1).* = Descriptor{
        .address = request.physical,
        .flags = @enumToInt(Descriptor.Flag.next),
        .length = @intCast(u32, request_bytes.len),
        .next = descriptor2,
    };

    driver.control_queue.push_available(descriptor1);
    driver.mmio.notify_queue();
}

fn handler() void {
    // TODO: use more than one driver
    const driver = if (Graphics.drivers.len > 0) @ptrCast(*Driver, Graphics.drivers[0]) else initialization_driver;
    const descriptor = driver.control_queue.pop_used() orelse @panic("virtio GPU descriptor corrupted");
    const header = @intToPtr(*volatile ControlHeader, kernel.arch.Virtual.AddressSpace.physical_to_virtual(descriptor.address));
    const request_descriptor = driver.control_queue.get_descriptor(descriptor.next) orelse @panic("unable to request descriptor");

    if (driver.initialized) {
        TODO(@src());
    } else {
        handle_ex(driver, header, request_descriptor, true);
    }
}

fn handle_ex(driver: *Driver, header: *volatile ControlHeader, request_descriptor: *volatile Descriptor, comptime initializing: bool) void {
    const control_header = @intToPtr(*ControlHeader, kernel.arch.Virtual.AddressSpace.physical_to_virtual(request_descriptor.address));
    switch (header.type) {
        .cmd_get_display_info => {
            defer {
                if (initializing) driver.received_display_info = true;
            }

            driver.display_info = @ptrCast(*ResponseDisplayInfo, control_header).*;
        },
        .cmd_resource_create_2d, .cmd_resource_attach_backing, .cmd_set_scanout, .cmd_transfer_to_host_2d, .cmd_resource_flush => {
            if (control_header.type != ControlType.resp_ok_nodata) {
                kernel.panic("Unable to process {s} request successfully: {s}", .{ @tagName(header.type), @tagName(control_header.type) });
            }

            log.debug("Processed {s} successfully", .{@tagName(header.type)});
        },
        else => kernel.panic("Header not implemented: {s}", .{@tagName(header.type)}),
    }

    if (header.type == ControlType.cmd_transfer_to_host_2d) driver.transfered = true;
    if (header.type == ControlType.cmd_resource_flush) driver.flushed = true;
}

var initialization_driver: *Driver = undefined;

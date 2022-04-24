const kernel = @import("../../kernel.zig");
const TODO = kernel.TODO;

const page_size = kernel.arch.page_size;

const ring_size = 128;

pub const MMIO = struct {
    magic_value: u32,
    version: u32,
    device_id: u32,
    vendor_id: u32,

    device_features: u32,
    device_feature_selector: u32,
    reserved1: [8]u8,

    driver_features: u32,
    driver_feature_selector: u32,
    reserved2: [8]u8,

    queue_selector: u32,
    queue_num_max: u32,
    queue_num: u32,
    reserved3: [4]u8,

    reserved4: [4]u8,
    queue_ready: u32,
    reserved5: [8]u8,

    queue_notify: u32,
    reserved6: [12]u8,

    interrupt_status: u32,
    interrupt_ack: u32,
    reserved7: [8]u8,

    status: u32,
    reserved8: [12]u8,

    queue_descriptor_low: u32,
    queue_descriptor_high: u32,
    reserved9: [8]u8,

    queue_available_low: u32,
    queue_available_high: u32,
    reserved10: [8]u8,

    queue_used_low: u32,
    queue_used_high: u32,
    reserved11: [8]u8,

    reserved12: [0x4c]u8,
    config_gen: u32,

    const magic = 0x74726976;
    const version = 2;

    pub fn init(self: *volatile @This()) void {
        if (self.magic_value != magic) @panic("virtio magic corrupted");
        if (self.version != version) @panic("outdated virtio spec");
        if (self.device_id == 0) @panic("invalid device");

        // 1. Reset
        self.status = 0;

        // 2. Ack the device
        self.status |= @enumToInt(Status.acknowledge);

        // 3. The driver knows how to use the device
        self.status |= @enumToInt(Status.driver);

        // 4. Read device feature bits and write (a subset of) them
        var features = self.device_features;
        // Disable VIRTIO F RING EVENT INDEX
        features &= ~@as(u32, 1 << 29);
        self.driver_features = features;

        // 5. Set features ok status bit
        self.status |= @enumToInt(Status.features_ok);

        if (self.status & @enumToInt(Status.features_ok) == 0) @panic("unsupported features");
    }

    pub inline fn set_driver_initialized(self: *volatile @This()) void {
        self.status |= @enumToInt(MMIO.Status.driver);
    }

    pub inline fn notify_queue(self: *volatile @This()) void {
        self.queue_notify = 0;
    }

    pub fn add_queue_to_device(self: *volatile @This(), selected_queue: u32) *volatile Queue {
        if (self.queue_num_max < ring_size) {
            @panic("foooo");
        }
        self.queue_selector = selected_queue;
        self.queue_num = ring_size;

        if (self.queue_ready != 0) @panic("queue ready");

        const total_size = @sizeOf(Queue) + (@sizeOf(Descriptor) * ring_size) + @sizeOf(Available) + @sizeOf(Used);
        const page_count = total_size / page_size + @boolToInt(total_size % page_size != 0);
        // All physical address space is identity-mapped so mapping is not needed here
        const queue_physical = kernel.arch.Physical.allocate1(page_count) orelse @panic("unable to allocate memory for virtio block device queue");
        const queue = @intToPtr(*volatile Queue, kernel.arch.Virtual.AddressSpace.physical_to_virtual(queue_physical));
        // TODO: distinguist between physical and virtual
        queue.num = 0;
        queue.last_seen_used = 0;
        queue.descriptors = @intToPtr(@TypeOf(queue.descriptors), @ptrToInt(queue) + @sizeOf(Queue));
        // identity-mapped
        const physical = @ptrToInt(queue);
        const descriptor = physical + @sizeOf(Queue);
        queue.available = @intToPtr(@TypeOf(queue.available), @ptrToInt(queue) + @sizeOf(Queue) + (ring_size * @sizeOf(Descriptor)));
        const available = physical + @sizeOf(Queue) + (ring_size * @sizeOf(Descriptor));
        queue.available.flags = 0;
        queue.available.index = 0;
        queue.used = @intToPtr(@TypeOf(queue.used), @ptrToInt(queue) + @sizeOf(Queue) + (ring_size * @sizeOf(Descriptor)) + @sizeOf(Available));
        const used = physical + @sizeOf(Queue) + (ring_size * @sizeOf(Descriptor)) + @sizeOf(Available);
        queue.used.flags = 0;
        queue.used.index = 0;

        // notify device of queue
        self.queue_num = ring_size;

        // specify queue structs
        self.queue_descriptor_low = @truncate(u32, descriptor);
        self.queue_descriptor_high = @truncate(u32, descriptor >> 32);
        self.queue_available_low = @truncate(u32, available);
        self.queue_available_high = @truncate(u32, available >> 32);
        self.queue_used_low = @truncate(u32, used);
        self.queue_used_high = @truncate(u32, used >> 32);

        self.queue_ready = 1;

        return queue;
    }

    const Status = enum(u32) {
        acknowledge = 1 << 0,
        driver = 1 << 1,
        features_ok = 1 << 7,
    };

    const log = kernel.log.scoped(.MMIO);
};

pub const Descriptor = struct {
    address: u64,
    length: u32,
    flags: u16,
    next: u16,

    pub const Flag = enum(u16) {
        next = 1 << 0,
        write_only = 1 << 1,
        indirect = 1 << 2,
    };
};

const Available = struct {
    flags: u16,
    index: u16,
    ring: [ring_size]u16,
    event: u16,
    padding: [2]u8,
};

const Used = struct {
    flags: u16,
    index: u16,
    ring: [ring_size]Entry,
    event: u16,

    const Entry = struct {
        id: u32,
        length: u32,
    };
};

const Queue = struct {
    num: u32,
    last_seen_used: u32,
    descriptors: [*]volatile Descriptor,
    available: *volatile Available,
    used: *volatile Used,

    fn push_descriptor(self: *volatile @This(), p_descriptor_index: *u16) *volatile Descriptor {
        // TODO Cause for a bug
        p_descriptor_index.* = @intCast(u16, self.num);
        const descriptor = &self.descriptors[self.num];
        self.num += 1;

        while (self.num >= ring_size) : (self.num -= ring_size) {}

        return descriptor;
    }

    fn push_available(self: *volatile @This(), descriptor: u16) void {
        self.available.ring[self.available.index % ring_size] = descriptor;
        self.available.index += 1;
    }

    pub fn pop_used(self: *volatile @This()) ?*volatile Descriptor {
        if (self.last_seen_used == self.used.index) return null;

        const id = self.used.ring[self.last_seen_used % ring_size].id;
        self.last_seen_used += 1;
        const used = &self.descriptors[id];

        return used;
    }

    pub fn get_descriptor(self: *volatile @This(), descriptor_id: u16) ?*volatile Descriptor {
        if (descriptor_id < ring_size) return &self.descriptors[descriptor_id] else return null;
    }
};

pub const block = struct {
    var queue: *volatile Queue = undefined;
    var mmio: *volatile MMIO = undefined;
    pub var read: u64 = 0;

    const log = kernel.log.scoped(.VirtioBlock);

    const BlockType = enum(u32) {
        in = 0,
        out = 1,
        flush = 4,
        discard = 11,
        write_zeroes = 13,
    };

    const Request = struct {
        const Header = struct {
            block_type: BlockType,
            reserved: u32,
            sector: u64,
        };
    };

    const Operation = enum {
        read,
        write,
    };

    pub fn init(mmio_address: u64) void {
        kernel.arch.Virtual.map(mmio_address, 1);
        mmio = @intToPtr(*volatile MMIO, mmio_address);
        mmio.init();
        queue = mmio.add_queue_to_device(0);
        // TODO: stop hardcoding interrupt number
        kernel.arch.Interrupts.register_external_interrupt_handler(8, handler);
        mmio.set_driver_initialized();

        log.debug("Block driver initialized", .{});
    }

    /// The sector buffer address needs to be physical and have at least 512 (sector_size) bytes available
    pub fn operate(comptime operation: Operation, sector_index: u64, sector_buffer_physical_address: u64) void {
        const status_size = 1;
        const header_size = @sizeOf(Request.Header);

        const status_buffer = kernel.heap.allocate(status_size, true, true) orelse @panic("status buffer unable to be allocated");
        const header_buffer = kernel.heap.allocate(header_size, true, true) orelse @panic("header buffer unable to be allocated");
        // TODO: Here we should distinguish between virtual and physical addresses
        const header = @intToPtr(*Request.Header, header_buffer.virtual);
        header.block_type = switch (operation) {
            .read => BlockType.in,
            .write => BlockType.out,
        };
        header.sector = sector_index;

        var descriptor1: u16 = 0;
        var descriptor2: u16 = 0;
        var descriptor3: u16 = 0;

        queue.push_descriptor(&descriptor3).* = Descriptor{
            .address = status_buffer.physical,
            .flags = @enumToInt(Descriptor.Flag.write_only),
            .length = 1,
            .next = 0,
        };

        queue.push_descriptor(&descriptor2).* = Descriptor{
            .address = sector_buffer_physical_address,
            .flags = @enumToInt(Descriptor.Flag.next) | if (operation == Operation.read) @enumToInt(Descriptor.Flag.write_only) else 0,
            .length = kernel.arch.sector_size,
            .next = descriptor3,
        };

        queue.push_descriptor(&descriptor1).* = Descriptor{
            .address = header_buffer.physical,
            .flags = @enumToInt(Descriptor.Flag.next),
            .length = @sizeOf(Request.Header),
            .next = descriptor2,
        };

        queue.push_available(descriptor1);
        mmio.notify_queue();
    }

    var lock: kernel.Spinlock = undefined;
    pub fn handler() void {
        const descriptor = queue.pop_used() orelse @panic("descriptor corrupted");
        // TODO Get virtual of this physical address @Virtual @Physical
        const header = @intToPtr(*volatile Request.Header, kernel.arch.Virtual.AddressSpace.physical_to_virtual(descriptor.address));
        const operation: Operation = switch (header.block_type) {
            .in => .read,
            .out => .write,
            else => unreachable,
        };
        _ = operation;
        const sector_descriptor = queue.get_descriptor(descriptor.next) orelse @panic("unable to get descriptor");

        const status_descriptor = queue.get_descriptor(sector_descriptor.next) orelse @panic("unable to get descriptor");
        const status = @intToPtr([*]u8, kernel.arch.Virtual.AddressSpace.physical_to_virtual(status_descriptor.address))[0];
        //log.debug("Disk operation status: {}", .{status});
        if (status != 0) @panic("Disk operation failed");

        read += kernel.arch.sector_size;
    }
};

pub const gpu = struct {
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

    var mmio: *volatile MMIO = undefined;
    var control_queue: *volatile Queue = undefined;
    var cursor_queue: *volatile Queue = undefined;
    var transfered = false;
    var flushed = false;

    const log = kernel.log.scoped(.VirtioGPU);

    pub fn init(mmio_address: u64) void {
        kernel.arch.Virtual.map(mmio_address, 1);
        mmio = @intToPtr(*volatile MMIO, mmio_address);
        mmio.init();

        control_queue = mmio.add_queue_to_device(0);
        cursor_queue = mmio.add_queue_to_device(1);

        // TODO: stop hardcoding interrupt number
        kernel.arch.Interrupts.register_external_interrupt_handler(7, handler);
        mmio.set_driver_initialized();

        var header = kernel.zeroes(ControlHeader);
        header.type = ControlType.cmd_get_display_info;
        operate(kernel.as_bytes(&header), @sizeOf(ResponseDisplayInfo));
        while (!received_display_info) {}
        if (display_info.header.type != ControlType.resp_ok_display_info) {
            @panic("display info corrupted");
        }

        log.debug("Display info", .{});
        for (display_info.pmodes) |pmode_it, i| {
            if (pmode_it.enabled != 0) log.debug("[{}] pmode: {}", .{ i, pmode_it });
        }
        pmode = display_info.pmodes[0];

        var create = kernel.zeroes(ResourceCreate2D);
        create.header.type = ControlType.cmd_resource_create_2d;
        create.format = Format.R8G8B8A8_UNORM;
        create.resource_id = 1;
        create.width = pmode.rect.width;
        create.height = pmode.rect.height;

        operate(kernel.as_bytes(&create), @sizeOf(ControlHeader));

        const framebuffer_pixel_count = pmode.rect.width * pmode.rect.height;
        const framebuffer_size = @sizeOf(u32) * framebuffer_pixel_count;
        const framebuffer_allocation = kernel.heap.allocate(framebuffer_size, true, true) orelse @panic("unable to allocate framebuffer");

        // Fill the kernel framebuffer object outside the driver
        kernel.framebuffer.buffer = @intToPtr([*]u32, framebuffer_allocation.virtual);
        kernel.framebuffer.width = pmode.rect.width;
        kernel.framebuffer.height = pmode.rect.height;

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
        operate(@intToPtr([*]u8, backing_allocation.virtual)[0..backing_size], @sizeOf(ControlHeader));

        var set_scanout = kernel.zeroes(SetScanout);
        set_scanout.header.type = ControlType.cmd_set_scanout;
        set_scanout.rect = pmode.rect;
        set_scanout.resource_id = 1;

        operate(kernel.as_bytes(&set_scanout), @sizeOf(ControlHeader));

        const framebuffer = @intToPtr([*]u32, framebuffer_allocation.virtual)[0..framebuffer_pixel_count];
        for (framebuffer) |*pixel| {
            pixel.* = 0xffffffff;
        }

        send_and_flush_framebuffer();

        log.debug("GPU driver initialized", .{});
    }

    pub fn send_and_flush_framebuffer() void {
        var transfer_to_host = kernel.zeroes(TransferControlToHost2D);
        transfer_to_host.header.type = ControlType.cmd_transfer_to_host_2d;
        transfer_to_host.rect = pmode.rect;
        transfer_to_host.resource_id = 1;

        log.debug("Sending transfer", .{});
        transfered = false;
        operate(kernel.as_bytes(&transfer_to_host), @sizeOf(ControlHeader));
        while (!transfered) {}

        var flush = kernel.zeroes(ResourceFlush);
        flush.header.type = ControlType.cmd_resource_flush;
        flush.rect = pmode.rect;
        flush.resource_id = 1;

        log.debug("Sending flush", .{});
        flushed = false;
        operate(kernel.as_bytes(&flush), @sizeOf(ControlHeader));
        while (!flushed) {}
    }

    pub fn operate(request_bytes: []const u8, response_size: u32) void {
        const request = kernel.heap.allocate(request_bytes.len, true, true) orelse @panic("unable to allocate memory for gpu request");
        kernel.copy(u8, @intToPtr([*]u8, request.virtual)[0..request_bytes.len], request_bytes);

        var descriptor1: u16 = 0;
        var descriptor2: u16 = 0;

        control_queue.push_descriptor(&descriptor2).* = Descriptor{
            .address = (kernel.heap.allocate(response_size, true, true) orelse @panic("unable to get memory for gpu response")).physical,
            .flags = @enumToInt(Descriptor.Flag.write_only),
            .length = response_size,
            .next = 0,
        };

        control_queue.push_descriptor(&descriptor1).* = Descriptor{
            .address = request.physical,
            .flags = @enumToInt(Descriptor.Flag.next),
            .length = @intCast(u32, request_bytes.len),
            .next = descriptor2,
        };

        control_queue.push_available(descriptor1);
        mmio.notify_queue();
    }

    var display_info: ResponseDisplayInfo = undefined;
    var received_display_info = false;
    var pmode: ResponseDisplayInfo.Display = undefined;
    var initialized = false;

    fn handler() void {
        const descriptor = control_queue.pop_used() orelse @panic("descriptor corrupted");
        const header = @intToPtr(*volatile ControlHeader, kernel.arch.Virtual.AddressSpace.physical_to_virtual(descriptor.address));
        const request_descriptor = control_queue.get_descriptor(descriptor.next) orelse @panic("unable to request descriptor");

        if (initialized) {
            TODO(@src());
        } else {
            handle_ex(header, request_descriptor, true);
        }
    }

    fn handle_ex(header: *volatile ControlHeader, request_descriptor: *volatile Descriptor, comptime initializing: bool) void {
        const control_header = @intToPtr(*ControlHeader, kernel.arch.Virtual.AddressSpace.physical_to_virtual(request_descriptor.address));
        switch (header.type) {
            .cmd_get_display_info => {
                defer {
                    if (initializing) received_display_info = true;
                }

                display_info = @ptrCast(*ResponseDisplayInfo, control_header).*;
            },
            .cmd_resource_create_2d, .cmd_resource_attach_backing, .cmd_set_scanout, .cmd_transfer_to_host_2d, .cmd_resource_flush => {
                if (control_header.type != ControlType.resp_ok_nodata) {
                    kernel.panic("Unable to process {s} request successfully: {s}", .{ @tagName(header.type), @tagName(control_header.type) });
                }

                log.debug("Processed {s} successfully", .{@tagName(header.type)});
            },
            else => kernel.panic("Header not implemented: {s}", .{@tagName(header.type)}),
        }

        if (header.type == ControlType.cmd_transfer_to_host_2d) transfered = true;
        if (header.type == ControlType.cmd_resource_flush) flushed = true;
    }
};

comptime {
    kernel.reference_all_declarations(@This());
}

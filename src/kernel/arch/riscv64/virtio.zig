const kernel = @import("../../kernel.zig");
const TODO = kernel.TODO;

// TODO: make possible to instantiate more than one same-class virtio driver

const page_size = kernel.arch.page_size;

const ring_size = 128;

pub const Block = @import("virtio_block.zig");
pub const GPU = @import("virtio_gpu.zig");

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

    device_status: DeviceStatus,
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
        self.device_status = DeviceStatus.empty();
        if (self.device_status.bits != 0) @panic("Device status should be 0");

        // 2. Ack the device
        self.device_status.or_flag(.acknowledge);

        // 3. The driver knows how to use the device
        self.device_status.or_flag(.driver);

        // 4. Read device feature bits and write (a subset of) them
        var features = self.device_features;
        log.debug("Features: {b}", .{features});
        // Disable VIRTIO F RING EVENT INDEX
        features &= ~@as(u32, 1 << 29);
        self.driver_features = features;

        // 5. Set features ok status bit
        self.device_status.or_flag(.features_ok);

        if (!self.device_status.contains(.features_ok)) @panic("unsupported features");
    }

    pub inline fn set_driver_initialized(self: *volatile @This()) void {
        self.device_status.or_flag(.driver_ok);
    }

    pub inline fn notify_queue(self: *volatile @This()) void {
        self.queue_notify = 0;
    }

    pub fn add_queue_to_device(self: *volatile @This(), selected_queue: u32) *volatile SplitQueue {
        if (self.queue_num_max < ring_size) {
            @panic("foooo");
        }
        self.queue_selector = selected_queue;
        self.queue_num = ring_size;

        if (self.queue_ready != 0) @panic("queue ready");

        const total_size = @sizeOf(SplitQueue) + (@sizeOf(Descriptor) * ring_size) + @sizeOf(Available) + @sizeOf(Used);
        const page_count = total_size / page_size + @boolToInt(total_size % page_size != 0);
        // All physical address space is identity-mapped so mapping is not needed here
        const queue_physical = kernel.arch.Physical.allocate1(page_count) orelse @panic("unable to allocate memory for virtio block device queue");
        const queue = @intToPtr(*volatile SplitQueue, kernel.arch.Virtual.AddressSpace.physical_to_virtual(queue_physical));
        // TODO: distinguist between physical and virtual
        queue.num = 0;
        queue.last_seen_used = 0;
        queue.descriptors = @intToPtr(@TypeOf(queue.descriptors), @ptrToInt(queue) + @sizeOf(SplitQueue));
        // identity-mapped
        const physical = @ptrToInt(queue);
        const descriptor = physical + @sizeOf(SplitQueue);
        queue.available = @intToPtr(@TypeOf(queue.available), @ptrToInt(queue) + @sizeOf(SplitQueue) + (ring_size * @sizeOf(Descriptor)));
        const available = physical + @sizeOf(SplitQueue) + (ring_size * @sizeOf(Descriptor));
        queue.available.flags = 0;
        queue.available.index = 0;
        queue.used = @intToPtr(@TypeOf(queue.used), @ptrToInt(queue) + @sizeOf(SplitQueue) + (ring_size * @sizeOf(Descriptor)) + @sizeOf(Available));
        const used = physical + @sizeOf(SplitQueue) + (ring_size * @sizeOf(Descriptor)) + @sizeOf(Available);
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

    pub const DeviceStatus = kernel.Bitflag(true, enum(u32) {
        acknowledge = 0,
        driver = 1,
        driver_ok = 2,
        features_ok = 3,
        device_needs_reset = 6,
        failed = 7,
    });

    const Features = enum(u32) {
        ring_indirect_descriptors = 28,
        ring_event_index = 29,
        version_1 = 32,
        access_platform = 33,
        ring_packed = 34,
        in_order = 35,
        order_platform = 36,
        single_root_io_virtualization = 37,
        notification_data = 38,
    };

    const log = kernel.log.scoped(.MMIO);

    pub fn debug_device_status(mmio: *volatile MMIO) void {
        log.debug("Reading device status...", .{});
        const device_status = mmio.device_status;
        for (kernel.enum_values(DeviceStatus)) |flag| {
            if (device_status & @enumToInt(flag) != 0) {
                log.debug("Flag set: {}", .{flag});
            }
        }
    }
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

pub const SplitQueue = struct {
    num: u32,
    last_seen_used: u32,
    descriptors: [*]volatile Descriptor,
    available: *volatile Available,
    used: *volatile Used,

    pub fn push_descriptor(queue: *volatile SplitQueue, p_descriptor_index: *u16) *volatile Descriptor {
        // TODO Cause for a bug
        p_descriptor_index.* = @intCast(u16, queue.num);
        const descriptor = &queue.descriptors[queue.num];
        queue.num += 1;

        while (queue.num >= ring_size) : (queue.num -= ring_size) {}

        return descriptor;
    }

    pub fn push_available(queue: *volatile SplitQueue, descriptor: u16) void {
        queue.available.ring[queue.available.index % ring_size] = descriptor;
        queue.available.index += 1;
    }

    pub fn pop_used(queue: *volatile SplitQueue) ?*volatile Descriptor {
        if (queue.last_seen_used == queue.used.index) return null;

        const id = queue.used.ring[queue.last_seen_used % ring_size].id;
        queue.last_seen_used += 1;
        const used = &queue.descriptors[id];

        return used;
    }

    pub fn get_descriptor(queue: *volatile SplitQueue, descriptor_id: u16) ?*volatile Descriptor {
        if (descriptor_id < ring_size) return &queue.descriptors[descriptor_id] else return null;
    }
};

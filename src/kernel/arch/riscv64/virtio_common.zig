const kernel = @import("../../kernel.zig");
const TODO = kernel.TODO;

const print = kernel.arch.early_print;
const write = kernel.arch.early_write;
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
        const magic_value = self.magic_value;
        print("0x{x}\n", .{magic_value});
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

    pub fn add_queue_to_device(self: *volatile @This(), selected_queue: u32) *volatile Queue {
        print("Queue max: {}\n", .{self.queue_num_max});
        if (self.queue_num_max < ring_size) {
            @panic("foooo");
        }
        self.queue_selector = selected_queue;
        self.queue_num = ring_size;

        if (self.queue_ready != 0) @panic("queue ready");

        const total_size = @sizeOf(Queue) + (@sizeOf(Descriptor) * ring_size) + @sizeOf(Available) + @sizeOf(Used);
        const page_count = total_size / page_size + @boolToInt(total_size % page_size != 0);
        // All physical address space is identity-mapped so mapping is not needed here
        const queue = @intToPtr(*volatile Queue, kernel.arch.Physical.allocate(page_count, true) orelse @panic("unable to allocate memory for virtio block device queue"));
        queue.num = 0;
        queue.last_seen_used = 0;
        queue.descriptor = @intToPtr(@TypeOf(queue.descriptor), @ptrToInt(queue) + @sizeOf(Queue));
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

        write("notify of queue\n");
        // notify device of queue
        self.queue_num = ring_size;

        // specify queue structs
        self.queue_descriptor_low = @truncate(u32, descriptor);
        self.queue_descriptor_high = @truncate(u32, descriptor >> 32);
        self.queue_available_low = @truncate(u32, available);
        self.queue_available_high = @truncate(u32, available >> 32);
        self.queue_used_low = @truncate(u32, used);
        self.queue_used_high = @truncate(u32, used >> 32);

        write("sending queue ready\n");
        self.queue_ready = 1;

        return queue;
    }

    const Status = enum(u32) {
        acknowledge = 1 << 0,
        driver = 1 << 1,
        features_ok = 1 << 7,
    };
};

pub const Descriptor = struct {
    address: u64,
    length: u32,
    flags: u16,
    next: u16,

    pub const Flag = enum(u32) {
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
    descriptor: *volatile Descriptor,
    available: *volatile Available,
    used: *volatile Used,
};

pub const block = struct {
    var queue: *volatile Queue = undefined;
    pub fn init(mmio_address: u64) void {
        kernel.arch.Virtual.map(mmio_address, 1);
        const mmio = @intToPtr(*volatile MMIO, mmio_address);
        mmio.init();
        queue = mmio.add_queue_to_device(0);
        mmio.status |= @enumToInt(MMIO.Status.driver);
        write("Block driver initialized\n");
        TODO(@src());
    }
};

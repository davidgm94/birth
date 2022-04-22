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
    const sector_size = 512;

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
        mmio.status |= @enumToInt(MMIO.Status.driver);

        log.debug("Block driver initialized", .{});
    }

    /// The sector buffer address needs to be physical and have at least 512 bytes available
    pub fn perform_block_operation(comptime operation: Operation, sector_index: u64, sector_buffer_physical_address: u64) void {
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
            .length = 512,
            .next = descriptor3,
        };

        queue.push_descriptor(&descriptor1).* = Descriptor{
            .address = header_buffer.physical,
            .flags = @enumToInt(Descriptor.Flag.next),
            .length = @sizeOf(Request.Header),
            .next = descriptor2,
        };

        queue.push_available(descriptor1);
        mmio.queue_notify = 0;
    }

    var lock: kernel.Spinlock = undefined;
    pub fn handler() void {
        lock.acquire();
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

        read += 512;
        lock.release();
    }
};

pub var read: u64 = 0;

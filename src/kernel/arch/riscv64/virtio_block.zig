const kernel = @import("../../kernel.zig");
const TODO = kernel.TODO;
const virtio = @import("virtio.zig");

const block_size = 512;

pub const Device = struct {
    queue: *virtio.Queue,
    address: u64,
    index: u16,
    ack_used_index: u16,
    read_only: bool,

    pub fn access(self: *@This(), buffer: []u8, size: u32, offset: u64, operation: Operation, watcher: u16) void {
        if (self.read_only and operation == .write) @panic("Trying to write to read-only device");

        if (size & (block_size - 1) != 0) @panic("Size is not block-aligned");

        const sector = offset / block_size;
        // TODO @Heap
        kernel.assert(@src(), @sizeOf(Request) < kernel.arch.page_size);
        const request = @intToPtr(*Request, kernel.arch.physical.allocate_pages(1) orelse @panic("unable to allocate for block request\n"));
        var head_index: u16 = 0;
        {
            const descriptor = virtio.Descriptor{
                .address = @ptrToInt(&request.header),
                .len = @sizeOf(Header),
                .flags = virtio.Descriptor.Flags.next,
                .next = 0,
            };

            head_index = self.fill_next_descriptor(descriptor);
        }

        request.header.sector = sector;
        request.header.block_type = if (operation == .write) BlockType.out else BlockType.in;

        request.data = @ptrToInt(buffer.ptr);
        request.header.reserved = 0;
        request.status = 111;
        request.watcher = watcher;

        {
            const descriptor = virtio.Descriptor{
                .address = @ptrToInt(buffer.ptr),
                .len = size,
                .flags = virtio.Descriptor.Flags.next | @as(u16, if (operation != .write) virtio.Descriptor.Flags.write else 0),
                .next = 0,
            };

            const data_index = self.fill_next_descriptor(descriptor);
            _ = data_index;
        }

        {
            const descriptor = virtio.Descriptor{
                .address = @ptrToInt(&request.status),
                .len = @sizeOf(@TypeOf(request.status)),
                .flags = virtio.Descriptor.Flags.write,
                .next = 0,
            };

            const status_index = self.fill_next_descriptor(descriptor);
            _ = status_index;
        }

        self.queue.available.ring[self.queue.available.index % virtio.ring_size] = head_index;
        self.queue.available.index = self.queue.available.index +% 1;

        @intToPtr(*volatile u32, self.address + @enumToInt(virtio.Offset.queue_notify)).* = 0;
    }

    fn fill_next_descriptor(self: *@This(), descriptor: virtio.Descriptor) u16 {
        self.index = (self.index + 1) % virtio.ring_size;
        self.queue.descriptor[self.index] = descriptor;
        if (self.queue.descriptor[self.index].flags & virtio.Descriptor.Flags.next != 0) {
            self.queue.descriptor[self.index].next = (self.index + 1) % virtio.ring_size;
        }

        return self.index;
    }
};

const Operation = enum {
    read,
    write,
};

// TODO: Provide a better type than an enum
const BlockType = enum(u32) {
    in = 0,
    out = 1,
    flush = 4,
    discard = 11,
    write_zeroes = 13,
};

const Header = struct {
    block_type: BlockType,
    reserved: u32,
    sector: u64,
};

const Request = struct {
    header: Header,
    data: u64,
    status: u8,
    head: u16,
    watcher: u16,
};

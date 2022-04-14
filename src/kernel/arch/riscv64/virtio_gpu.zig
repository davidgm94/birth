const std = @import("std");
const kernel = @import("../../kernel.zig");
const TODO = kernel.TODO;
const virtio = @import("virtio.zig");
const Descriptor = virtio.Descriptor;
const ring_size = virtio.ring_size;
const physical = kernel.arch.physical;

const logger = std.log.scoped(.virtio_gpu);

fn Communication(comptime Request: type) type {
    return struct {
        request: Request,
        response: ControlHeader,

        comptime {
            std.debug.assert(@sizeOf(@This()) <= kernel.arch.page_size);
        }
    };
}

fn CommunicationWithMemoryEntry(comptime Request: type) type {
    return struct {
        request: Request,
        memory_entry: MemoryEntry,
        response: ControlHeader,

        comptime {
            std.debug.assert(@sizeOf(@This()) <= kernel.arch.page_size);
        }
    };
}

const MemoryEntry = struct {
    address: u64,
    len: u32,
    padding: u32,
};

pub const Pixel = struct {
    r: u8,
    g: u8,
    b: u8,
    a: u8,
};

const ControlType = enum(u32) {
    // 2D commands
    command_get_display_info = 0x100,
    command_resource_create_2D = 0x101,
    command_resource_uref = 0x102,
    command_set_scanout = 0x103,
    command_resource_flush = 0x104,
    command_transfer_to_host_2d = 0x105,
    command_resource_attach_backing = 0x106,
    command_resource_detach_backing = 0x107,
    command_get_capset_info = 0x108,
    command_get_capset = 0x109,
    command_get_edid = 0x10a,

    // Cursor commands
    command_update_cursor = 0x300,
    command_move_cursor = 0x301,

    // Responses (success)
    response_ok_no_data = 0x1100,
    response_ok_no_display_info = 0x1101,
    response_ok_capset_info = 0x1102,
    response_ok_capset = 0x1103,
    response_ok_edid = 0x1104,

    // Responses (error)
    response_error_unspec = 0x1200,
    response_error_out_of_memory = 0x1201,
    response_error_invalid_scanout_id = 0x1202,
    response_error_invalid_resource_id = 0x1203,
    response_error_invalid_context_id = 0x1204,
    response_error_invalid_parameter = 0x1205,
};

const Format = enum(u32) {
    B8_G8_R8_A8_Unorm = 1,
    B8_G8_R8_X8_Unorm = 2,
    A8_R8_G8_B8_Unorm = 3,
    X8_R8_G8_B8_Unorm = 4,
    R8_G8_B8_A8_Unorm = 67,
    X8_B8_G8_R8_Unorm = 68,
    A8_B8_G8_R8_Unorm = 121,
    R8_G8_B8_X8_Unorm = 134,
};

const ControlHeader = struct {
    type: ControlType,
    flags: u32 = 0,
    fence_id: u64 = 0,
    context_id: u32 = 0,
    padding: u32 = 0,
};

const ResourceCreate2D = struct {
    header: ControlHeader = .{ .type = .command_resource_create_2D },
    resource_id: u32,
    format: Format,
    width: u32,
    height: u32,
};

const AttachBacking = struct {
    header: ControlHeader = .{ .type = .command_resource_attach_backing },
    resource_ID: u32,
    entry_count: u32,
};

const Rect = struct {
    x: u32,
    y: u32,
    width: u32,
    height: u32,
};

const SetScanout = struct {
    header: ControlHeader = .{ .type = .command_set_scanout },
    rect: Rect,
    scanout_ID: u32,
    resource_ID: u32,
};

const TransferToHost2D = struct {
    header: ControlHeader = .{ .type = .command_transfer_to_host_2d },
    rect: Rect,
    offset: u64,
    resource_ID: u32,
    padding: u32,
};

const ResourceFlush = struct {
    header: ControlHeader = .{ .type = .command_resource_flush },
    rect: Rect,
    resource_ID: u32,
    padding: u32,
};

pub const Device = struct {
    queue: *virtio.Queue,
    address: u64,
    index: u16,
    ack_used_index: u16,
    framebuffer: [*]Pixel,
    width: u32,
    height: u32,

    fn fill_all(self: @This(), color: Pixel) void {
        std.mem.set(Pixel, self.framebuffer[0 .. self.width * self.height], color);
    }

    pub fn new_communication(self: *@This(), comptime Request: type, request: Request) void {
        const page = physical.allocate_pages(1) orelse @panic("unable to get page for VIRTIO GPU communication\n");
        const communication = @intToPtr(*Communication(Request), page);
        communication.request = request;

        const head = self.index;
        self.queue.descriptor[self.index] = Descriptor{
            .address = @ptrToInt(&communication.request),
            .len = @sizeOf(Request),
            .flags = Descriptor.Flags.next,
            .next = (self.index + 1) % ring_size,
        };
        self.index = (self.index + 1) % ring_size;

        self.queue.descriptor[self.index] = Descriptor{
            .address = @ptrToInt(&communication.response),
            .len = @sizeOf(ControlHeader),
            .flags = Descriptor.Flags.write,
            .next = 0,
        };
        self.index = (self.index + 1) % ring_size;
        self.queue.available.ring[self.queue.available.index % ring_size] = head;
        // Wrapping add
        self.queue.available.index = self.queue.available.index +% 1;
    }

    pub fn new_communication_with_memory_entry(self: *@This(), comptime Request: type, request: Request, memory_entry: MemoryEntry) void {
        const page = physical.allocate_pages(1) orelse @panic("unable to get page for VIRTIO GPU communication\n");
        const communication = @intToPtr(*CommunicationWithMemoryEntry(Request), page);
        communication.request = request;
        communication.memory_entry = memory_entry;

        const head = self.index;
        self.queue.descriptor[self.index] = Descriptor{
            .address = @ptrToInt(&communication.request),
            .len = @sizeOf(Request),
            .flags = Descriptor.Flags.next,
            .next = (self.index + 1) % ring_size,
        };
        self.index = (self.index + 1) % ring_size;

        self.queue.descriptor[self.index] = Descriptor{
            .address = @ptrToInt(&communication.memory_entry),
            .len = @sizeOf(MemoryEntry),
            .flags = Descriptor.Flags.next,
            .next = (self.index + 1) % ring_size,
        };
        self.index = (self.index + 1) % ring_size;

        self.queue.descriptor[self.index] = Descriptor{
            .address = @ptrToInt(&communication.response),
            .len = @sizeOf(ControlHeader),
            .flags = Descriptor.Flags.write,
            .next = 0,
        };
        self.index = (self.index + 1) % ring_size;
        self.queue.available.ring[self.queue.available.index % ring_size] = head;
        // Wrapping add
        self.queue.available.index = self.queue.available.index +% 1;
    }

    pub fn init(self: *@This()) void {
        self.fill_all(Pixel{ .r = 255, .g = 255, .b = 255, .a = 255 });

        // 1. Create a host resource using create 2D
        self.new_communication(ResourceCreate2D, .{
            .resource_id = 1,
            .format = Format.R8_G8_B8_A8_Unorm,
            .width = self.width,
            .height = self.height,
        });

        // 2. Attach backing
        self.new_communication_with_memory_entry(AttachBacking, .{
            .resource_ID = 1,
            .entry_count = 1,
        }, MemoryEntry{
            .address = @ptrToInt(self.framebuffer),
            .len = self.width * self.height * @sizeOf(Pixel),
            .padding = 0,
        });

        self.new_communication(SetScanout, SetScanout{
            .rect = Rect{ .x = 0, .y = 0, .width = self.width, .height = self.height },
            .scanout_ID = 0,
            .resource_ID = 1,
        });

        self.new_communication(TransferToHost2D, TransferToHost2D{
            .rect = Rect{ .x = 0, .y = 0, .width = self.width, .height = self.height },
            .offset = 0,
            .resource_ID = 1,
            .padding = 0,
        });

        self.new_communication(ResourceFlush, ResourceFlush{
            .rect = .{ .x = 0, .y = 0, .width = self.width, .height = self.height },
            .resource_ID = 1,
            .padding = 0,
        });

        self.run_queue();
        self.fill_all(Pixel{ .r = 0, .g = 122, .b = 0, .a = 255 });
        self.transfer(0, 0, self.width, self.height);
        logger.info("GPU device initialized", .{});
    }

    pub fn run_queue(self: @This()) void {
        @intToPtr(*volatile u32, self.address + @enumToInt(virtio.Offset.queue_notify)).* = 0;
    }

    pub fn transfer(self: *@This(), x: u32, y: u32, width: u32, height: u32) void {
        const rect = Rect{ .x = x, .y = y, .width = width, .height = height };
        self.new_communication(TransferToHost2D, TransferToHost2D{
            .rect = rect,
            .offset = 0,
            .resource_ID = 1,
            .padding = 0,
        });

        self.new_communication(ResourceFlush, ResourceFlush{
            .rect = rect,
            .resource_ID = 1,
            .padding = 0,
        });

        self.run_queue();
    }
};

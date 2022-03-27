const kernel = @import("../../kernel.zig");
const std = @import("std");
const last = 0x1000_1000;
const first = 0x1000_8000;
const log = std.log.scoped(.virtio);
const device_size = 0x1000;
const page_size = kernel.arch.page_size;
const TODO = kernel.TODO;
const physical = kernel.arch.physical;
const virtual = kernel.arch.virtual;

pub const GPU = @import("virtio_gpu.zig");
pub const Block = @import("virtio_block.zig");

const DeviceID = enum(u32) {
    network = 1,
    block = 2,
    RNG = 4,
    GPU = 16,
    input = 18,

    fn get(device_id_int: u32) ?DeviceID {
        for (std.enums.values(DeviceID)) |value| {
            if (@enumToInt(value) == device_id_int) {
                return value;
            }
        }

        return null;
    }
};

pub const ring_size = 1 << 7;

pub const Descriptor = struct {
    address: u64,
    len: u32,
    flags: u16,
    next: u16,

    pub const Flags = struct {
        pub const next = 1 << 0;
        pub const write = 1 << 1;
        pub const indirect = 1 << 2;
    };
};

pub const Available = struct {
    flags: u16,
    index: u16,
    ring: [ring_size]u16,
    event: u16,
};

pub var gpu: GPU.Device = undefined;
pub var block: Block.Device = undefined;

pub const Used = struct {
    pub const Element = struct {
        id: u32,
        len: u32,
    };

    flags: u16,
    index: u16,
    ring: [ring_size]Used.Element,
    event: u16,
};

pub const Queue = struct {
    descriptor: [ring_size]Descriptor,
    available: Available,
    padding: [page_size - (@sizeOf(Descriptor) * ring_size) - @sizeOf(Available)]u8,
    used: Used,
};

pub fn DeviceProcessor(comptime device_base: u64) type {
    return struct {
        fn parse() void {
            const magic_value = ptr(.magic_value).*;
            if (magic_value != 0x74726976) return;

            const device_ID_int = ptr(.device_id).*;
            if (device_ID_int == 0) return; // not connected

            const device_ID = DeviceID.get(device_ID_int) orelse @panic("unknown device id\n");

            // Common initialization
            var status: u32 = 0;
            const status_ptr = ptr(.status);
            status_ptr.* = status;

            status |= @enumToInt(Status.acknowledge);
            status_ptr.* = status;
            status |= @enumToInt(Status.driver_ok);
            status_ptr.* = status;

            const host_features = ptr(.host_features).*;
            ptr(.guest_features).* = host_features;

            status |= @enumToInt(Status.features_ok);
            status_ptr.* = status;

            const status_ok = status_ptr.*;
            if (status_ok & @enumToInt(Status.features_ok) == 0) {
                @panic("feature activation failed\n");
            }

            // Device-specific initialization
            switch (device_ID) {
                .block => {
                    const queue_ptr = setup_queue();
                    block = Block.Device {
                        .queue = queue_ptr,
                        .address = device_base,
                        .index = 0,
                        .ack_used_index = 0,
                        .read_only = false,
                    };
                    driver_ok(status_ptr, status);
                    log.info("Block device detected", .{});
                },
                .GPU => {
                    const queue_ptr = setup_queue();
                    const framebuffer_page_count = (page_size * 2 + 640 * 480 * @sizeOf(GPU.Pixel)) / page_size;
                    const framebuffer_address = physical.allocate_pages(framebuffer_page_count) orelse @panic("Framebuffer allocation failed\n");

                    gpu = .{
                        .queue = queue_ptr,
                        .address = device_base,
                        .index = 0,
                        .ack_used_index = 0,
                        .framebuffer = @intToPtr([*]GPU.Pixel, framebuffer_address),
                        .width = 640,
                        .height = 480,
                    };

                    driver_ok(status_ptr, status);
                    log.info("GPU device detected", .{});
                },
                else => {
                    log.warn("Unhandled device: {s}", .{@tagName(device_ID)});
                },
            }
        }
        fn driver_ok(status_ptr: *volatile u32, status: u32) void {
            status_ptr.* = status | @enumToInt(Status.driver_ok);
        }

        fn setup_queue() *Queue {
            const queue_max_count = ptr(.queue_num_max).*;
            if (queue_max_count < ring_size) @panic("ring size not ok\n");
            ptr(.queue_num).* = ring_size;

            const queue_page_count = (@sizeOf(Queue) + page_size - 1) / page_size;
            ptr(.queue_sel).* = 0;
            ptr(.guest_page_size).* = page_size;

            const queue_ptr = @intToPtr(*Queue, physical.allocate_pages(queue_page_count) orelse @panic("queue ptr not available\n"));
            std.mem.set(u8, @ptrCast([*]u8, queue_ptr)[0 .. page_size * queue_page_count], 0);
            const queue_pfn = @truncate(u32, @ptrToInt(queue_ptr));
            ptr(.queue_pfn).* = queue_pfn / page_size;

            return queue_ptr;
        }

        fn ptrT(comptime T: type, comptime offset: Offset) *volatile T {
            return @intToPtr(*volatile T, device_base + @enumToInt(offset));
        }

        fn ptr(comptime offset: Offset) *volatile u32 {
            return ptrT(u32, offset);
        }
    };
}

pub const Offset = enum(u32) {
    magic_value = 0,
    version = 4,
    device_id = 8,
    vendor_id = 0xc,
    host_features = 0x10,
    host_features_sel = 0x14,
    guest_features = 0x20,
    guest_features_sel = 0x24,
    guest_page_size = 0x28,
    queue_sel = 0x30,
    queue_num_max = 0x34,
    queue_num = 0x38,
    queue_align = 0x3c,
    queue_pfn = 0x40,
    queue_notify = 0x50,
    interrupt_status = 0x60,
    interrupt_ack = 0x64,
    status = 0x70,
    config = 0x100,
};

pub const Status = enum(u32) {
    acknowledge = 1,
    driver = 2,
    driver_ok = 4,
    features_ok = 8,
    needs_reset = 64,
    failed = 128,
};

pub fn init() void {
    comptime var mmio_it: u64 = first;
    virtual.map(last, first + device_size - last);
    inline while (mmio_it >= last) : (mmio_it -= device_size) {
        DeviceProcessor(mmio_it).parse();
    }
}

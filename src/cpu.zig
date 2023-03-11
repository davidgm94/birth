const lib = @import("lib");

const privileged = @import("privileged");
const PageAllocator = privileged.PageAllocator;
const VirtualAddressSpace = privileged.VirtualAddressSpace;

const bootloader = @import("bootloader");

pub fn panic(comptime format: []const u8, arguments: anytype) noreturn {
    privileged.arch.disableInterrupts();
    privileged.writer.writeAll("[CPU DRIVER] [PANIC] ") catch unreachable;
    privileged.writer.print(format, arguments) catch unreachable;
    privileged.writer.writeByte('\n') catch unreachable;
    privileged.arch.stopCPU();
}

pub const test_runner = @import("cpu/test_runner.zig");

pub const arch = @import("cpu/arch.zig");

pub export var stack: [0x4000]u8 align(0x1000) = undefined;
pub export var virtual_address_space: VirtualAddressSpace = undefined;

pub export var mappings: extern struct {
    text: privileged.Mapping = .{},
    rodata: privileged.Mapping = .{},
    data: privileged.Mapping = .{},
} = .{};

pub export var page_allocator = PageAllocator{
    .head = null,
    .list_allocator = .{
        .u = .{
            .primitive = .{
                .backing_4k_page = undefined,
                .allocated = 0,
            },
        },
        .primitive = true,
    },
};

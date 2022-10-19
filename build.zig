const common = @import("src/common.zig");
const Build = @import("src/build/lib.zig");
const Arch = Build.Arch;

pub fn build(b: *Build.Builder) void {
    const kernel = b.allocator.create(Build.Kernel) catch unreachable;
    kernel.* = Build.Kernel{
        .builder = b,
        .allocator = Build.get_allocator(),
        .options = .{
            .arch = Build.Kernel.Options.x86_64.new(.{
                .bootloader = .inhouse,
            }),
            .run = .{
                .disks = &.{
                    .{
                        .interface = .ahci,
                        .filesystem = .RNU,
                    },
                },
                .memory = .{
                    .amount = 4,
                    .unit = .G,
                },
                .emulator = .{
                    .qemu = .{
                        .vga = .std,
                        .smp = null,
                        .log = .{
                            .file = null,
                            .guest_errors = true,
                            .cpu = false,
                            .assembly = false,
                            .interrupts = true,
                        },
                        .virtualize = true,
                        .print_command = true,
                    },
                },
            },
        },
    };

    kernel.create();
}

const common = @import("../common.zig");
const context = @import("context");
const ExitStatus = common.ExitStatus;
const TODO = common.TODO;
pub fn exit(exit_status: ExitStatus) noreturn {
    switch (common.cpu.arch) {
        .x86_64 => {
            common.arch.x86_64.io_write(x86_isa_debug_exit.type, x86_isa_debug_exit.port, @enumToInt(exit_status));
        },
        else => TODO(@src()),
    }
    unreachable;
}

pub const x86_isa_debug_exit = struct {
    port: u16 = 0xf4,
    type: type = u32,
}{};

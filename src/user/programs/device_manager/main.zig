const lib = @import("lib");
const log = lib.log;
const user = @import("user");
const Syscall = user.Syscall;

pub const panic = user.zigPanic;
pub const std_options = user.std_options;

export var core_id: u32 = 0;

pub fn main() !noreturn {
    core_id = try Syscall(.cpu, .get_core_id).blocking({});
    user.currentScheduler().core_id = core_id;
    log.debug("Hello world! User space initialization from core #{}", .{core_id});
    const allocation = try Syscall(.cpu_memory, .allocate).blocking(0x1000);
    log.debug("Look allocation successful at 0x{x}", .{allocation.value()});
    try Syscall(.cpu, .shutdown).blocking({});
}

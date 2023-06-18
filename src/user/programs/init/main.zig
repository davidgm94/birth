const lib = @import("lib");
const log = lib.log;
const user = @import("user");
const syscall = user.Syscall;

pub const panic = user.zigPanic;
pub const std_options = user.std_options;

export var core_id: u32 = 0;

pub fn main() !noreturn {
    core_id = try syscall(.cpu, .get_core_id).blocking({});
    user.currentScheduler().core_id = core_id;
    log.debug("Hello world! User space initialization from core #{}", .{core_id});
    const bundle_file_list_size = try syscall(.boot, .get_bundle_file_list_size).blocking({});
    log.debug("Bundle file list size: {}", .{bundle_file_list_size});
    const bundle_size = try syscall(.boot, .get_bundle_size).blocking({});
    log.debug("Bundle size: {}", .{bundle_size});
    const allocation = try syscall(.cpu_memory, .allocate).blocking(0x1000);
    log.debug("Look allocation successful at 0x{x}", .{allocation.value()});
    try syscall(.cpu, .shutdown).blocking({});
}

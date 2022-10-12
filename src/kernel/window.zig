const Window = @This();

pub const Manager = @import("window_manager.zig");

const common = @import("common");

const RNU = @import("RNU");
const Thread = RNU.Thread;

id: u64,
user: *common.Window,
thread: *Thread,
alpha: u8 = 0xff,

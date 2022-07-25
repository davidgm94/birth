const common = @import("../../common.zig");
const log = common.log.scoped(.Syscall);
const TODO = common.TODO;

pub const Syscall = common.Syscall;

pub const RawHandler = fn (argument0: u64, argument1: u64, argument2: u64, argument3: u64, argument4: u64, argument5: u64) callconv(.C) Syscall.Result;
pub const Handler = fn (argument0: u64, argument1: u64, argument2: u64, argument3: u64, argument4: u64, argument5: u64) callconv(.C) Syscall.Result;
pub const raw_handlers = [Syscall.raw_count]RawHandler{
    common.safe_function_cast(ask_syscall_manager, .{ .FunctionType = RawHandler }) catch |err| @compileLog(err),
};

pub noinline fn ask_syscall_manager() callconv(.C) void {}

//pub fn thread_exit(syscall_id: Syscall.ID, exit_code: u64, maybe_message_ptr: ?[*]const u8, message_len: u64, _: u64, _: u64) callconv(.C) noreturn {
//common.runtime_assert(@src(), syscall_id == .thread_exit);
//log.debug("We are thread exiting with code: 0x{x}", .{exit_code});
//if (maybe_message_ptr) |message_ptr| {
//if (message_len != 0) {
//const user_message = message_ptr[0..message_len];
//log.debug("User message: {s}", .{user_message});
//} else {
//log.err("Message pointer is valid but user didn't specify valid length", .{});
//}
//}

//TODO(@src());
//}

const common = @import("common");
pub const panic = common.User.panic;
pub const log = common.User.log;
pub const logger = common.log.scoped(.main);

const Syscall = common.Syscall;
const ask_syscall_manager = Syscall.ask_syscall_manager;
pub var syscall_manager: *Syscall.Manager = undefined;
pub var writer: common.Writer(void, Writer.Error, Writer.write) = undefined;

export fn _start() callconv(.C) void {
    syscall_manager = ask_syscall_manager() orelse @panic("wtf");
    logger.debug("Wtf", .{});
    while (true) {}
}

const Writer = struct {
    const Error = error{};

    fn write(_: void, bytes: []const u8) Error!usize {
        syscall_manager.add_submission(Syscall.log(bytes));
        syscall_manager.flush();

        return bytes.len;
    }
};

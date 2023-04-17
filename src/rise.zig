const lib = @import("lib");

pub const arch = @import("rise/arch.zig");
pub const capabilities = @import("rise/capabilities.zig");
pub const syscall = @import("rise/syscall.zig");

/// This struct is the shared part that the user and the cpu see
pub const UserScheduler = extern struct {
    valid: bool = false,

    pub inline fn architectureSpecific(user_scheduler: *UserScheduler) *arch.UserScheduler {
        return @fieldParentPtr(arch.UserScheduler, "generic", user_scheduler);
    }
};

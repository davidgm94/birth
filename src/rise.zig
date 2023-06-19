const lib = @import("lib");

pub const arch = @import("rise/arch.zig");
pub const capabilities = @import("rise/capabilities.zig");
pub const syscall = @import("rise/syscall.zig");

/// This struct is the shared part that the user and the cpu see
pub const UserScheduler = extern struct {
    self: *UserScheduler,
    disabled: bool,
    has_work: bool,
    core_id: u32,
    setup_stack: [lib.arch.valid_page_sizes[0]]u8 align(lib.arch.stack_alignment),
    setup_stack_lock: lib.Atomic(bool),

    pub inline fn architectureSpecific(user_scheduler: *UserScheduler) *arch.UserScheduler {
        return @fieldParentPtr(arch.UserScheduler, "generic", user_scheduler);
    }
};

pub const CommandBuffer = struct {
    foo: u32,
};

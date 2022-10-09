const common = @import("common");

pub const ID = enum(u64) {
    desktop_setup_ui = 0,
};

pub const count = common.enum_count(ID);

id: ID,
context: ?*anyopaque,

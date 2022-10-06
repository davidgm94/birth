const Process = @This();

const common = @import("common");
const ListFile = common.List;

const RNU = @import("RNU");

type: Type,
id: u64,

pub const Type = enum {
    kernel,
    desktop,
    user,
};

pub fn create(process_type: Type) ?*Process {
    _ = process_type;
    @panic("todo process_create");
}

pub const ListItem = ListFile.ListItem(*Process);
pub const List = ListFile.List(*Process);
pub const Buffer = ListFile.BufferList(Process, 64);

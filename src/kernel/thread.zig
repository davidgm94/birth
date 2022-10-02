const Thread = @This();

const common = @import("common");
const ListFile = common.List;

const RNU = @import("RNU");
const Graphics = RNU.Graphics;
const Framebuffer = Graphics.Framebuffer;
const PrivilegeLevel = RNU.PrivilegeLevel;
const Process = RNU.Process;
const Syscall = RNU.Syscall;
const VirtualAddress = RNU.VirtualAddress;
const VirtualAddressSpace = RNU.VirtualAddressSpace;

const arch = @import("arch");
const Context = arch.Context;
const CPU = arch.CPU;

//const std = @import("../common/std.zig");

//const arch = @import("arch/common.zig");
//const common = @import("common.zig");
//const Context = arch.Context;
//const CPU = arch.CPU;
//const VirtualAddress = @import("virtual_address.zig");
//const PrivilegeLevel = @import("scheduler_common.zig").PrivilegeLevel;
//const VirtualAddressSpace = @import("virtual_address_space.zig");
//const Syscall = @import("syscall.zig");
//const ListFile = @import("../common/list.zig");

kernel_stack: VirtualAddress,
privilege_level: PrivilegeLevel,

type: Type,
state: State,
kernel_stack_base: VirtualAddress,
kernel_stack_size: u64,
user_stack_base: VirtualAddress,
user_stack_size: u64,
id: u64,
context: *Context,
time_slices: u64,
address_space: *VirtualAddressSpace,
cpu: ?*CPU,
process: *Process,
syscall_manager: Syscall.KernelManager,
all_item: ListItem,
queue_item: ListItem,
framebuffer: *Framebuffer,
executing: bool,

pub const Type = enum(u1) {
    normal = 0,
    idle = 1,
};

pub const EntryPoint = struct {
    start_address: u64,
    argument: u64,
};

pub const State = enum {
    paused,
    active,
};

pub const ListItem = ListFile.ListItem(*Thread);
pub const List = ListFile.List(*Thread);
pub const Buffer = ListFile.StableBuffer(Thread, 64);

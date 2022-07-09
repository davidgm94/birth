const Thread = @This();

const common = @import("../common.zig");
const VirtualAddress = common.VirtualAddress;
const PrivilegeLevel = common.PrivilegeLevel;
const VirtualAddressSpace = common.VirtualAddressSpace;

current_thread: *Thread,
kernel_stack: VirtualAddress,
privilege_level: PrivilegeLevel,
type: Type,
kernel_stack_base: VirtualAddress,
kernel_stack_size: u64,
user_stack_base: VirtualAddress,
user_stack_reserve: u64,
user_stack_commit: u64,
id: u64,
context: *common.arch.Context,
time_slices: u64,
last_known_execution_address: u64,
address_space: *VirtualAddressSpace,
cpu: ?*common.arch.CPU,

// TODO: idle thread
const Type = enum(u1) {
    normal = 0,
    idle = 1,
};

pub const EntryPoint = struct {
    start_address: u64,
    argument: u64,
};

const Process = @This();

const common = @import("common");
const ListFile = common.List;

const rise = @import("rise");
const Executable = rise.Executable;
const panic = rise.panic;
const PrivilegeLevel = rise.PrivilegeLevel;
const Thread = rise.Thread;
const VirtualAddressSpace = rise.VirtualAddressSpace;

const kernel = @import("kernel");

type: Type,
id: u64,
virtual_address_space: *VirtualAddressSpace,
main_thread: *Thread,

pub const Type = enum {
    kernel,
    desktop,
    user,
};

pub fn from_executable_in_memory(process_type: Type, executable: Executable.InKernelMemory) !*Process {
    if (process_type == .kernel) {
        @panic("Trying to load kernel executable from file");
    }

    const virtual_address_space = try kernel.memory.virtual_address_spaces.add_one(kernel.virtual_address_space.heap.allocator);
    virtual_address_space.initialize_user_address_space();

    const entry_point = try Executable.load_into_user_memory(virtual_address_space, executable);

    const process = try kernel.memory.processes.add_one(kernel.virtual_address_space.heap.allocator);
    process.* = Process{
        .type = process_type,
        .id = process.id, // Save the same id
        .virtual_address_space = virtual_address_space,
        .main_thread = undefined,
    };

    process.main_thread = try kernel.scheduler.spawn_thread(.user, entry_point, process);

    return process;
}

pub const ListItem = ListFile.ListItem(*Process);
pub const List = ListFile.List(*Process);
pub const Buffer = ListFile.BufferList(Process, 64);

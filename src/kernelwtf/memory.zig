const common = @import("common");
const Buffer = common.List.BufferList;

const rise = @import("rise");
const Process = rise.Process;
const Thread = rise.Thread;
const VirtualAddressSpace = rise.VirtualAddressSpace;
const Window = rise.Window;

const arch = @import("arch");
const CPU = arch.CPU;

const max_cpu_count = 256;

threads: Buffer(Thread, max_cpu_count, true) = .{}, // This is just a preset value for thread buffer blocks, it is dynamic
processes: Buffer(Process, 64, true) = .{},
virtual_address_spaces: Buffer(VirtualAddressSpace, 64, true) = .{},
windows: Buffer(Window, 64, true) = .{},
// Both these values are static
cpus: common.List.GlobalStaticBuffer(CPU, max_cpu_count) = .{},
current_threads: common.List.GlobalStaticBuffer(*Thread, max_cpu_count) = .{},

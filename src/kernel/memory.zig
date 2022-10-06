const common = @import("common");
const Buffer = common.List.BufferList;

const RNU = @import("RNU");
const Process = RNU.Process;
const Thread = RNU.Thread;
const VirtualAddressSpace = RNU.VirtualAddressSpace;

const arch = @import("arch");
const CPU = arch.CPU;

const max_cpu_count = 256;

threads: Buffer(Thread, max_cpu_count) = .{}, // This is just a preset value for thread buffer blocks, it is dynamic
processes: Buffer(Process, 64) = .{},
virtual_address_spaces: Buffer(VirtualAddressSpace, 64) = .{},
// Both these values are static
cpus: common.List.GlobalStaticBuffer(CPU, max_cpu_count) = .{},
current_threads: common.List.GlobalStaticBuffer(*Thread, max_cpu_count) = .{},

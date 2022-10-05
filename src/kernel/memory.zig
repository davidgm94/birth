const common = @import("common");
const Buffer = common.List.BufferList;

const RNU = @import("RNU");
const Process = RNU.Process;
const Thread = RNU.Thread;
const VirtualAddressSpace = RNU.VirtualAddressSpace;

const arch = @import("arch");
const CPU = arch.CPU;

threads: Buffer(Thread, 256) = .{},
processes: Buffer(Process, 64) = .{},
virtual_address_spaces: Buffer(VirtualAddressSpace, 64) = .{},
cpus: common.List.GlobalStaticBuffer(CPU, 256) = .{},

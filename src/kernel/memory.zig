const RNU = @import("RNU");
const Process = RNU.Process;
const Thread = RNU.Thread;
const VirtualAddressSpace = RNU.VirtualAddressSpace;

threads: Thread.Buffer = .{},
processes: Process.Buffer = .{},
virtual_address_spaces: VirtualAddressSpace.Buffer = .{},
current_threads: []*Thread = &.{},

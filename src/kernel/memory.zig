const Memory = @This();

const RNU = @import("RNU");
const Process = RNU.Process;
const Thread = RNU.Thread;
const VirtualAddressSpace = RNU.VirtualAddressSpace;

thread: Thread.Buffer,
process: Process.Buffer,
virtual_address_space: VirtualAddressSpace.Buffer,
current_threads: []*Thread,

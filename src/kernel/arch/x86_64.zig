const kernel = @import("root");
const common = @import("common");
const drivers = @import("../../drivers.zig");
const PCI = drivers.PCI;
const NVMe = drivers.NVMe;
const Virtio = drivers.Virtio;
const Disk = drivers.Disk;
const Filesystem = drivers.Filesystem;
const RNUFS = drivers.RNUFS;

const TODO = common.TODO;
const Allocator = common.Allocator;
const PhysicalAddress = common.PhysicalAddress;
const PhysicalAddressSpace = common.PhysicalAddressSpace;
const PhysicalMemoryRegion = common.PhysicalMemoryRegion;
const VirtualAddress = common.VirtualAddress;
const VirtualAddressSpace = common.VirtualAddressSpace;
const VirtualMemoryRegion = common.VirtualMemoryRegion;

const log = common.log.scoped(.x86_64);

pub const entry = @import("x86_64/entry.zig");

const CPU = common.arch.CPU;
const Thread = common.arch.Thread;
const Context = common.arch.Context;

const x86_64 = common.arch.x86_64;
//
//pub extern fn switch_context(new_context: *Context, new_address_space: *AddressSpace, kernel_stack: u64, new_thread: *Thread, old_address_space: *VirtualAddressSpace) callconv(.C) void;
//pub export fn switch_context() callconv(.Naked) void {
//asm volatile (
//\\cli
//// Compare address spaces and switch if they are not the same
//\\mov (%%rsi), %%rsi
//\\mov %%cr3, %%rax
//\\cmp %%rsi, %%rax
//\\je 0f
//\\mov %%rsi, %%cr3
//\\0:
//\\mov %%rdi, %%rsp
//\\mov %%rcx, %%rsi
//\\mov %%r8, %%rdx
//);

//asm volatile (
//\\call post_context_switch
//);

//x86_64.interrupts.epilogue();

//unreachable;
//}

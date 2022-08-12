const common = @import("../common.zig");

const Thread = @import("thread.zig");
const arch = switch (common.cpu.arch) {
    .aarch64 => aarch64,
    .x86_64 => x86_64,
    else => @compileError("CPU architecture not supported"),
};

pub const aarch64 = @import("arch/aarch64.zig");
pub const x86_64 = @import("arch/x86_64.zig");

/// Arch-specific part of the address space
pub const VirtualAddressSpace = arch.VirtualAddressSpace;
pub const Spinlock = arch.Spinlock;
pub const CPU = arch.CPU;
pub const Context = arch.Context;
pub const Syscall = arch.Syscall;

pub const enable_interrupts = arch.enable_interrupts;
pub const disable_interrupts = arch.disable_interrupts;
pub const disable_all_interrupts = arch.disable_all_interrupts;
pub const are_interrupts_enabled = arch.are_interrupts_enabled;

pub const pci_read_config = arch.pci_read_config;
pub const pci_write_config = arch.pci_write_config;

pub const io_read = arch.io_read;
pub const io_write = arch.io_write;

pub const valid_page_sizes = arch.valid_page_sizes;

pub const next_timer = arch.next_timer;
pub const read_timestamp = arch.read_timestamp;

pub const allocate_and_setup_thread_pointers = arch.allocate_and_setup_thread_pointers;
pub const preset_thread_pointer = arch.preset_thread_pointer;
pub const set_current_thread = arch.set_current_thread;
pub const get_current_thread = arch.get_current_thread;

pub const get_memory_map = arch.get_memory_map;

pub const CPUFeatures = arch.CPUFeatures;

pub const cpu_start = arch.cpu_start;
pub const bootstrap_stacks = arch.bootstrap_stacks;

pub const init_block_drivers = arch.init_block_drivers;
pub const init_graphics_drivers = arch.init_graphics_drivers;

pub const Writer = struct {
    pub const Error = error{};
    pub var lock: arch.Spinlock = undefined;
    pub fn write(_: void, bytes: []const u8) Error!usize {
        return arch.writer_function(bytes);
    }
};

pub var writer = common.Writer(void, Writer.Error, Writer.write){ .context = {} };

pub const bootstrap_stack_size = 0x10000;

pub const switch_address_spaces_if_necessary = arch.switch_address_spaces_if_necessary;
pub const set_new_stack = arch.set_new_stack;
pub const post_context_switch = arch.post_context_switch;
pub const interrupts_epilogue = arch.interrupts_epilogue;
pub const set_argument = arch.set_argument;
pub const signal_end_of_interrupt = arch.signal_end_of_interrupt;
pub const legacy_actions_before_context_switch = arch.legacy_actions_before_context_switch;

pub const BootstrapContext = struct {
    cpu: CPU,
    thread: Thread,
    context: Context,
};

const root = @import("root");
const common = @import("../common.zig");
pub const kernel = @import("syscall/kernel.zig");
const context = @import("context");

const log = common.log.scoped(.Syscall);
const TODO = common.TODO;
const x86_64 = common.arch.x86_64;
const VirtualAddress = common.VirtualAddress;
const PhysicalAddress = common.PhysicalAddress;

pub const Result = extern struct {
    a: u64,
    b: u64,
};

pub const HardwareID = enum(u64) {
    ask_syscall_manager = 0,
};

pub const ID = enum(u64) {
    thread_exit = 0,
};

pub const raw_count = common.enum_values(ID).len;

const syscall = common.arch.Syscall.user_syscall_entry_point;

pub const ThreadExitParameters = struct {
    message: ?[]const u8 = null,
    exit_code: u64,
};

pub fn thread_exit(thread_exit_parameters: ThreadExitParameters) noreturn {
    var message_ptr: ?[*]const u8 = undefined;
    var message_len: u64 = undefined;
    if (thread_exit_parameters.message) |message| {
        message_ptr = message.ptr;
        message_len = message.len;
    } else {
        message_ptr = null;
        message_len = 0;
    }
    _ = syscall(@enumToInt(ID.thread_exit), thread_exit_parameters.exit_code, @ptrToInt(message_ptr), message_len, 0, 0);
    @panic("This syscall should not return");
}

const WorkEntry = struct {
    arguments: [6]u64,
};

const ResultEntry = struct {
    a: u64,
    b: u64,
};

pub const QueueDescriptor = struct {
    head: u32,
    tail: u32,
    offset: u32,
};

pub const KernelManager = struct {
    kernel: Manager,
    user: *Manager,
};

pub const Manager = struct {
    buffer: []u8,
    submission_queue: QueueDescriptor,
    completion_queue: QueueDescriptor,

    pub fn for_kernel(virtual_address_space: *common.VirtualAddressSpace, entry_count: u64) KernelManager {
        common.runtime_assert(@src(), virtual_address_space.privilege_level == .user);
        const submission_queue_buffer_size = common.align_forward(entry_count * @sizeOf(WorkEntry), context.page_size);
        const completion_queue_buffer_size = common.align_forward(entry_count * @sizeOf(ResultEntry), context.page_size);
        const total_buffer_size = submission_queue_buffer_size + completion_queue_buffer_size;

        const async_buffer_physical_address = root.physical_address_space.allocate(common.bytes_to_pages(total_buffer_size, context.page_size, .must_be_exact)) orelse @panic("wtF");
        // TODO: stop hardcoding
        const kernel_virtual_buffer = VirtualAddress.new(0x0000_7f00_0000_0000);
        const user_virtual_buffer = kernel_virtual_buffer.offset(total_buffer_size);
        const submission_physical_address = async_buffer_physical_address;
        const completion_physical_address = submission_physical_address.offset(submission_queue_buffer_size);
        virtual_address_space.map(submission_physical_address, kernel_virtual_buffer, .{ .write = false, .user = false });
        virtual_address_space.map(completion_physical_address, kernel_virtual_buffer.offset(submission_queue_buffer_size), .{ .write = true, .user = false });
        virtual_address_space.map(submission_physical_address, user_virtual_buffer, .{ .write = true, .user = true });
        virtual_address_space.map(completion_physical_address, user_virtual_buffer.offset(submission_queue_buffer_size), .{ .write = false, .user = true });

        // TODO: not use a full page
        // TODO: unmap
        // TODO: @Hack undo
        const user_async_manager_user_virtual = virtual_address_space.allocate(common.align_forward(@sizeOf(Manager), context.page_size), null, .{ .write = true, .user = true }) catch @panic("wtff");
        const translated_physical = virtual_address_space.translate_address(user_async_manager_user_virtual) orelse @panic("wtff");
        const kernel_virtual = translated_physical.to_higher_half_virtual_address();
        const trans_result = virtual_address_space.translate_address(kernel_virtual) orelse @panic("wtf");
        common.runtime_assert(@src(), trans_result.value == translated_physical.value);
        const user_async_manager = kernel_virtual.access(*Manager);
        user_async_manager.* = Manager{
            .buffer = user_virtual_buffer.access([*]u8)[0..total_buffer_size],
            .submission_queue = QueueDescriptor{
                .head = 0,
                .tail = 0,
                .offset = 0,
            },
            .completion_queue = QueueDescriptor{
                .head = 0,
                .tail = 0,
                .offset = @intCast(u32, submission_queue_buffer_size),
            },
        };

        return KernelManager{
            .kernel = Manager{
                .buffer = kernel_virtual_buffer.access([*]u8)[0..total_buffer_size],
                .submission_queue = QueueDescriptor{
                    .head = 0,
                    .tail = 0,
                    .offset = 0,
                },
                .completion_queue = QueueDescriptor{
                    .head = 0,
                    .tail = 0,
                    .offset = @intCast(u32, submission_queue_buffer_size),
                },
            },
            .user = user_async_manager_user_virtual.access(*Manager),
        };
    }
};

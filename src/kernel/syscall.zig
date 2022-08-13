const std = @import("../common/std.zig");
const context = @import("context.zig");
const Syscall = @import("../common/syscall.zig");
const kernel = @import("kernel.zig");

const VirtualAddress = @import("virtual_address.zig");
const VirtualAddressSpace = @import("virtual_address_space.zig");

pub const KernelManager = struct {
    kernel: ?*Syscall.Manager,
    user: ?*Syscall.Manager,

    pub fn new(virtual_address_space: *VirtualAddressSpace, entry_count: u64) KernelManager {
        std.unreachable_assert(@src(), virtual_address_space.privilege_level == .user);
        const submission_queue_buffer_size = std.align_forward(entry_count * @sizeOf(Syscall.Submission), context.page_size);
        const completion_queue_buffer_size = std.align_forward(entry_count * @sizeOf(Syscall.Completion), context.page_size);
        const total_buffer_size = submission_queue_buffer_size + completion_queue_buffer_size;

        const syscall_buffer_physical_address = kernel.physical_address_space.allocate(std.bytes_to_pages(total_buffer_size, context.page_size, .must_be_exact)) orelse @panic("wtF");
        const kernel_virtual_buffer = syscall_buffer_physical_address.to_higher_half_virtual_address();
        // TODO: stop hardcoding
        const user_virtual_buffer = VirtualAddress.new(0x0000_7f00_0000_0000);
        const submission_physical_address = syscall_buffer_physical_address;
        const completion_physical_address = submission_physical_address.offset(submission_queue_buffer_size);
        virtual_address_space.map(submission_physical_address, kernel_virtual_buffer, .{ .write = false, .user = false });
        virtual_address_space.map(completion_physical_address, kernel_virtual_buffer.offset(submission_queue_buffer_size), .{ .write = true, .user = false });
        virtual_address_space.map(submission_physical_address, user_virtual_buffer, .{ .write = true, .user = true });
        virtual_address_space.map(completion_physical_address, user_virtual_buffer.offset(submission_queue_buffer_size), .{ .write = false, .user = true });

        // TODO: not use a full page
        // TODO: unmap
        // TODO: @Hack undo
        const user_syscall_manager_virtual = virtual_address_space.allocate(std.align_forward(@sizeOf(Syscall.Manager), context.page_size), null, .{ .write = true, .user = true }) catch @panic("wtff");
        const translated_physical = virtual_address_space.translate_address(user_syscall_manager_virtual) orelse @panic("wtff");
        const kernel_syscall_manager_virtual = translated_physical.to_higher_half_virtual_address();
        const trans_result = virtual_address_space.translate_address(kernel_syscall_manager_virtual) orelse @panic("wtf");
        std.unreachable_assert(@src(), trans_result.value == translated_physical.value);
        const user_syscall_manager = kernel_syscall_manager_virtual.access(*Syscall.Manager);
        user_syscall_manager.* = Syscall.Manager{
            .buffer = user_virtual_buffer.access([*]u8)[0..total_buffer_size],
            .submission_queue = Syscall.QueueDescriptor{
                .head = 0,
                .tail = 0,
                .offset = 0,
            },
            .completion_queue = Syscall.QueueDescriptor{
                .head = 0,
                .tail = 0,
                .offset = @intCast(u32, submission_queue_buffer_size),
            },
        };

        const physical_kernel = virtual_address_space.translate_address(kernel_syscall_manager_virtual) orelse @panic("wtf");
        const physical_user = virtual_address_space.translate_address(user_syscall_manager_virtual) orelse @panic("wtf");
        std.unreachable_assert(@src(), physical_user.value == physical_kernel.value);

        return KernelManager{
            .kernel = kernel_syscall_manager_virtual.access(*Syscall.Manager),
            .user = user_syscall_manager_virtual.access(*Syscall.Manager),
        };
    }
};

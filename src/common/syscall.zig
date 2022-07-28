const root = @import("root");
const common = @import("../common.zig");
pub const kernel = @import("syscall/kernel.zig");
const context = @import("context");

const logger = common.log.scoped(.Syscall);
const TODO = common.TODO;
const x86_64 = common.arch.x86_64;
const VirtualAddress = common.VirtualAddress;
const PhysicalAddress = common.PhysicalAddress;

pub const RawResult = extern struct {
    a: u64,
    b: u64,
};

pub const Input = extern struct {
    id: u32,
    options: Options,

    comptime {
        common.comptime_assert(@sizeOf(Input) == @sizeOf(u64));
    }
};

pub const Options = packed struct {
    execution_mode: ExecutionMode,
    type: Type,
    unused: u30 = 0,
};

pub const Type = enum(u1) {
    hardware = 0,
    software = 1,
};

pub const HardwareID = enum(u32) {
    ask_syscall_manager = 0,
    flush_syscall_manager = 1,

    pub const count = common.enum_values(@This()).len;
};

pub const ID = enum(u32) {
    thread_exit = 0,
    log = 1,
    pub const count = common.enum_values(@This()).len;
};

const hardware_syscall_entry_point = common.arch.Syscall.user_syscall_entry_point;

pub const ThreadExitParameters = struct {
    message: ?[]const u8 = null,
    exit_code: u64 = 0,
};

pub fn immediate_syscall(submission: Submission) RawResult {
    return hardware_syscall_entry_point(submission.arguments[0], submission.arguments[1], submission.arguments[2], submission.arguments[3], submission.arguments[4], submission.arguments[5]);
}

pub fn hardware_syscall(comptime hw_syscall_id: HardwareID) RawResult {
    const input = Input{
        .id = @enumToInt(hw_syscall_id),
        .options = .{
            .execution_mode = .blocking,
            .type = .hardware,
        },
    };
    const inputed_bicasted = @bitCast(u64, input);
    return hardware_syscall_entry_point(inputed_bicasted, 0, 0, 0, 0, 0);
}

pub const LogParameters = struct {
    message: []const u8,
};
/// @Syscall
pub fn log(parameters: LogParameters) Submission {
    return new_submission(.log, @ptrToInt(parameters.message.ptr), parameters.message.len, 0, 0, 0);
}

pub fn new_submission(id: ID, argument1: u64, argument2: u64, argument3: u64, argument4: u64, argument5: u64) Submission {
    const input = Input{
        .id = @enumToInt(id),
        .options = .{
            .execution_mode = .blocking,
            .type = .software,
        },
    };
    const argument0 = @bitCast(u64, input);
    return Submission{ .arguments = [_]u64{
        argument0,
        argument1,
        argument2,
        argument3,
        argument4,
        argument5,
    } };
}

/// @Syscall
pub fn thread_exit(thread_exit_parameters: ThreadExitParameters) Submission {
    var message_ptr: ?[*]const u8 = undefined;
    var message_len: u64 = undefined;
    if (thread_exit_parameters.message) |message| {
        message_ptr = message.ptr;
        message_len = message.len;
    } else {
        message_ptr = null;
        message_len = 0;
    }

    return new_submission(.thread_exit, thread_exit_parameters.exit_code, @ptrToInt(message_ptr), message_len, 0, 0);
}

pub const ExecutionMode = enum(u1) {
    blocking,
    non_blocking,
    const count = common.enum_values(ExecutionMode).len;
};

const SyscallReturnType = blk: {
    var ReturnTypes: [ID.count][ExecutionMode.count]type = undefined;
    ReturnTypes[@enumToInt(ID.thread_exit)][@enumToInt(ExecutionMode.blocking)] = noreturn;
    ReturnTypes[@enumToInt(ID.thread_exit)][@enumToInt(ExecutionMode.non_blocking)] = void;
    ReturnTypes[@enumToInt(ID.log)][@enumToInt(ExecutionMode.blocking)] = void;
    ReturnTypes[@enumToInt(ID.log)][@enumToInt(ExecutionMode.non_blocking)] = void;
    break :blk ReturnTypes;
};

const SyscallParameters = blk: {
    var ParameterTypes: [ID.count]type = undefined;
    ParameterTypes[@enumToInt(ID.thread_exit)] = ThreadExitParameters;
    ParameterTypes[@enumToInt(ID.log)] = LogParameters;
    break :blk ParameterTypes;
};

pub const Submission = struct {
    arguments: [6]u64,
};

pub const Completion = RawResult;

pub const QueueDescriptor = struct {
    head: u32,
    tail: u32,
    offset: u32,
};

pub const KernelManager = struct {
    kernel: ?*Manager,
    user: ?*Manager,
};

pub const Manager = struct {
    buffer: []u8,
    submission_queue: QueueDescriptor,
    completion_queue: QueueDescriptor,

    pub fn for_kernel(virtual_address_space: *common.VirtualAddressSpace, entry_count: u64) KernelManager {
        common.runtime_assert(@src(), virtual_address_space.privilege_level == .user);
        const submission_queue_buffer_size = common.align_forward(entry_count * @sizeOf(Submission), context.page_size);
        const completion_queue_buffer_size = common.align_forward(entry_count * @sizeOf(Completion), context.page_size);
        const total_buffer_size = submission_queue_buffer_size + completion_queue_buffer_size;

        const syscall_buffer_physical_address = root.physical_address_space.allocate(common.bytes_to_pages(total_buffer_size, context.page_size, .must_be_exact)) orelse @panic("wtF");
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
        const user_syscall_manager_virtual = virtual_address_space.allocate(common.align_forward(@sizeOf(Manager), context.page_size), null, .{ .write = true, .user = true }) catch @panic("wtff");
        const translated_physical = virtual_address_space.translate_address(user_syscall_manager_virtual) orelse @panic("wtff");
        const kernel_syscall_manager_virtual = translated_physical.to_higher_half_virtual_address();
        const trans_result = virtual_address_space.translate_address(kernel_syscall_manager_virtual) orelse @panic("wtf");
        common.runtime_assert(@src(), trans_result.value == translated_physical.value);
        const user_syscall_manager = kernel_syscall_manager_virtual.access(*Manager);
        user_syscall_manager.* = Manager{
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

        const physical_kernel = virtual_address_space.translate_address(kernel_syscall_manager_virtual) orelse @panic("wtf");
        const physical_user = virtual_address_space.translate_address(user_syscall_manager_virtual) orelse @panic("wtf");
        common.runtime_assert(@src(), physical_user.value == physical_kernel.value);

        return KernelManager{
            .kernel = kernel_syscall_manager_virtual.access(*Manager),
            .user = user_syscall_manager_virtual.access(*Manager),
        };
    }

    pub fn syscall(manager: *Manager, comptime id: ID, comptime execution_mode: ExecutionMode, parameters: SyscallParameters[@enumToInt(id)]) SyscallReturnType[@enumToInt(id)][@enumToInt(execution_mode)] {
        const ReturnType = SyscallReturnType[@enumToInt(id)][@enumToInt(execution_mode)];
        const submission = switch (id) {
            .thread_exit => thread_exit(parameters),
            .log => log(parameters),
        };

        switch (execution_mode) {
            .blocking => {
                const result = immediate_syscall(submission);
                switch (ReturnType) {
                    noreturn, void => {},
                    else => return result,
                }
            },
            .non_blocking => {
                manager.add_submission(submission);
            },
        }

        if (ReturnType == noreturn) {
            @panic("should not have returned");
        }
    }

    fn add_submission(manager: *Manager, submission: Submission) void {
        const new = @ptrCast(*Submission, @alignCast(@alignOf(Submission), &manager.buffer[manager.submission_queue.offset + manager.submission_queue.head]));
        new.* = submission;
        manager.submission_queue.head += @sizeOf(Submission);
    }

    pub fn ask() ?*Manager {
        const result = hardware_syscall(.ask_syscall_manager);
        return @intToPtr(?*Manager, result.a);
    }

    pub fn flush(manager: *Manager) void {
        const submission_queue_head = manager.submission_queue.head;
        _ = hardware_syscall(.flush_syscall_manager);
        common.runtime_assert(@src(), manager.completion_queue.head == submission_queue_head);
    }
};

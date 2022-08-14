const std = @import("../common/std.zig");

const common = @import("../common/syscall.zig");

const ExecutionMode = common.ExecutionMode;
const HardwareID = common.HardwareID;
const Input = common.Input;
const QueueDescriptor = common.QueueDescriptor;
const RawResult = common.RawResult;
const ServiceID = common.ServiceID;
const Submission = common.Submission;
const SyscallParameters = common.SyscallParameters;
const SyscallReturnType = common.SyscallReturnType;

const LogParameters = common.LogParameters;
/// @Syscall
pub fn log(parameters: LogParameters) Submission {
    return new_submission(.log, @ptrToInt(parameters.message.ptr), parameters.message.len, 0, 0, 0);
}

const ReadFileParameters = common.ReadFileParameters;
/// @Syscall
pub fn read_file(parameters: ReadFileParameters) Submission {
    const file_name_address = @ptrToInt(parameters.name.ptr);
    const file_name_length = parameters.name.len;
    std.assert(file_name_address != 0);
    std.assert(file_name_length != 0);
    return new_submission(.read_file, file_name_address, file_name_length, 0, 0, 0);
}

const AllocateMemoryParameters = common.AllocateMemoryParameters;
/// @Syscall
pub fn allocate_memory(parameters: AllocateMemoryParameters) Submission {
    return new_submission(.allocate_memory, parameters.byte_count, parameters.alignment, 0, 0, 0);
}

const ThreadExitParameters = common.ThreadExitParameters;
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

pub fn new_submission(id: ServiceID, argument1: u64, argument2: u64, argument3: u64, argument4: u64, argument5: u64) Submission {
    const input = Input{
        .id = @enumToInt(id),
        .options = .{
            .execution_mode = .blocking,
            .type = .software,
        },
    };
    return Submission{ .input = input, .arguments = [_]u64{
        argument1,
        argument2,
        argument3,
        argument4,
        argument5,
    } };
}

pub const Manager = struct {
    buffer: []u8,
    submission_queue: QueueDescriptor,
    completion_queue: QueueDescriptor,

    pub fn syscall(manager: *Manager, comptime id: ServiceID, comptime execution_mode: ExecutionMode, parameters: SyscallParameters[@enumToInt(id)]) SyscallReturnType[@enumToInt(id)][@enumToInt(execution_mode)] {
        const ReturnType = SyscallReturnType[@enumToInt(id)][@enumToInt(execution_mode)];
        const submission = switch (id) {
            .thread_exit => thread_exit(parameters),
            .log => log(parameters),
            .read_file => read_file(parameters),
            .allocate_memory => allocate_memory(parameters),
        };

        switch (execution_mode) {
            .blocking => {
                const result = syscall_entry_point(submission.input, submission.arguments[0], submission.arguments[1], submission.arguments[2], submission.arguments[3], submission.arguments[4]);
                switch (ReturnType) {
                    noreturn, void => {},
                    else => switch (id) {
                        .read_file => {
                            if (@intToPtr(?[*]const u8, result.a)) |file_ptr| {
                                const file_len = result.b;
                                return file_ptr[0..file_len];
                            } else {
                                @panic("file could not be read");
                            }
                        },
                        else => @panic(@tagName(id)),
                    },
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
        std.assert(manager.completion_queue.head == submission_queue_head);
    }
};

pub fn hardware_syscall(comptime hw_syscall_id: HardwareID) RawResult {
    const input = Input{
        .id = @enumToInt(hw_syscall_id),
        .options = .{
            .execution_mode = .blocking,
            .type = .hardware,
        },
    };
    return syscall_entry_point(input, 0, 0, 0, 0, 0);
}

pub extern fn syscall_entry_point(arg0: Input, arg1: u64, arg2: u64, arg3: u64, arg4: u64, arg5: u64) callconv(.C) RawResult;

// INFO: only RSP is handled in the kernel
comptime {
    asm (
        \\.global syscall
        \\syscall_entry_point:
        \\push %r15
        \\push %r14
        \\push %r13
        \\push %r12
        \\push %rbx
        \\push %rbp
        \\mov %rcx, %rax
        \\syscall
        \\pop %rbp
        \\pop %rbx
        \\pop %r12
        \\pop %r13
        \\pop %r14
        \\pop %r15
        \\ret
    );
}

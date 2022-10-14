const common = @import("common");
const assert = common.assert;
const ExecutionMode = common.Syscall.ExecutionMode;
const QueueDescriptor = common.Syscall.Manager.QueueDescriptor;
const Service = common.Syscall.Service;
const Submission = common.Syscall.Submission;
const Syscall = common.Syscall.Syscall;

pub const Manager = struct {
    buffer: []u8,
    submission_queue: QueueDescriptor,
    completion_queue: QueueDescriptor,

    pub fn syscall(manager: *Manager, comptime id: Service.ID, comptime execution_mode: ExecutionMode, parameters: Service.ParametersType(id)) Service.ErrorType(id, execution_mode)!Service.ResultType(id, execution_mode) {
        const service = Service.from_id(id);
        const submission = try Submission.from_parameters(service, parameters);

        switch (execution_mode) {
            .blocking => {
                const result = syscall_entry_point(submission.input, submission.arguments[0], submission.arguments[1], submission.arguments[2], submission.arguments[3], submission.arguments[4]);
                switch (service.Result) {
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
                        .allocate_memory => {
                            const ptr = result.a;
                            const size = result.b;
                            if (size != parameters.size) {
                                @panic("size mismatch");
                            }
                            if (ptr == 0) {
                                @panic("nullptr");
                            }

                            return @intToPtr([*]u8, ptr)[0..size];
                        },
                        .get_framebuffer => {
                            const framebuffer = @intToPtr(*common.DrawingAreaDescriptor, result.a);
                            return framebuffer;
                        },
                        .receive_message => {
                            const message = common.Message{
                                .id = @intToEnum(common.Message.ID, result.a),
                                .context = @intToPtr(?*anyopaque, result.b),
                            };
                            return message;
                        },
                        else => @panic("User syscall not implemented: " ++ @tagName(id)),
                    },
                }

                if (service.Result == noreturn) {
                    @panic("should not have returned");
                }
            },
            .non_blocking => {
                manager.add_submission(submission);
            },
        }
    }

    fn add_submission(manager: *Manager, submission: Submission) void {
        const new = @ptrCast(*Submission, @alignCast(@alignOf(Submission), &manager.buffer[manager.submission_queue.offset + manager.submission_queue.head]));
        new.* = submission;
        manager.submission_queue.head += @sizeOf(Submission);
    }

    pub fn ask() ?*Manager {
        const result = perform_syscall(.ask_syscall_manager);
        return @intToPtr(?*Manager, result.a);
    }

    pub fn flush(manager: *Manager) void {
        const submission_queue_head = manager.submission_queue.head;
        _ = perform_syscall(.flush_syscall_manager);
        assert(manager.completion_queue.head == submission_queue_head);
    }
};

pub fn perform_syscall(comptime hw_syscall_id: Syscall.ID) Syscall.Result {
    const input = Submission.Input{
        .id = @enumToInt(hw_syscall_id),
        .options = .{
            .execution_mode = .blocking,
            .type = .syscall,
        },
    };
    return syscall_entry_point(input, 0, 0, 0, 0, 0);
}

pub extern fn syscall_entry_point(arg0: Submission.Input, arg1: u64, arg2: u64, arg3: u64, arg4: u64, arg5: u64) callconv(.C) Syscall.Result;

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

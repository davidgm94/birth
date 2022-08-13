const root = @import("root");
const common = @import("../common.zig");
pub const kernel = @import("syscall/kernel.zig");
const context = @import("context");

comptime {
    if (@import("builtin").os.tag != .freestanding) @compileError("This file should not be imported in build.zig");
}

const TODO = common.TODO;
const x86_64 = common.arch.x86_64;
const VirtualAddress = common.VirtualAddress;
const PhysicalAddress = common.PhysicalAddress;

pub const RawResult = extern struct {
    a: u64,
    b: u64,
};

pub const Input = extern struct {
    const IDIntType = u16;
    id: IDIntType,
    options: Options,

    comptime {
        common.comptime_assert(@sizeOf(Input) == @sizeOf(u64));
    }
};

pub const Options = packed struct {
    execution_mode: ExecutionMode,
    type: Type,
    unused: u46 = 0,
};

pub const Type = enum(u1) {
    hardware = 0,
    software = 1,
};

pub const HardwareID = enum(u16) {
    ask_syscall_manager = 0,
    flush_syscall_manager = 1,

    pub const count = common.enum_count(@This());
};

pub const ID = enum(u16) {
    thread_exit = 0,
    log = 1,
    read_file = 2,
    allocate_memory = 3,

    pub const count = common.enum_count(@This());
};

const hardware_syscall_entry_point = common.arch.Syscall.user_syscall_entry_point;

pub const ThreadExitParameters = struct {
    message: ?[]const u8 = null,
    exit_code: u64 = 0,
};

pub fn immediate_syscall(submission: Submission) RawResult {
    return hardware_syscall_entry_point(submission.input, submission.arguments[0], submission.arguments[1], submission.arguments[2], submission.arguments[3], submission.arguments[4]);
}

pub fn hardware_syscall(comptime hw_syscall_id: HardwareID) RawResult {
    const input = Input{
        .id = @enumToInt(hw_syscall_id),
        .options = .{
            .execution_mode = .blocking,
            .type = .hardware,
        },
    };
    return hardware_syscall_entry_point(input, 0, 0, 0, 0, 0);
}

pub const LogParameters = struct {
    message: []const u8,
};
/// @Syscall
pub fn log(parameters: LogParameters) Submission {
    return new_submission(.log, @ptrToInt(parameters.message.ptr), parameters.message.len, 0, 0, 0);
}

pub const ReadFileParameters = struct {
    name: []const u8,
};

pub fn read_file(parameters: ReadFileParameters) Submission {
    const file_name_address = @ptrToInt(parameters.name.ptr);
    const file_name_length = parameters.name.len;
    common.runtime_assert(@src(), file_name_address != 0);
    common.runtime_assert(@src(), file_name_length != 0);
    return new_submission(.read_file, file_name_address, file_name_length, 0, 0, 0);
}

pub const AllocateMemoryParameters = struct {
    byte_count: u64,
    alignment: u64,
};

pub fn allocate_memory(parameters: AllocateMemoryParameters) Submission {
    return new_submission(.allocate_memory, parameters.byte_count, parameters.alignment, 0, 0, 0);
}

pub fn new_submission(id: ID, argument1: u64, argument2: u64, argument3: u64, argument4: u64, argument5: u64) Submission {
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
    const count = common.enum_count(@This());
};

const SyscallReturnType = blk: {
    var ReturnTypes: [ID.count][ExecutionMode.count]type = undefined;
    ReturnTypes[@enumToInt(ID.thread_exit)][@enumToInt(ExecutionMode.blocking)] = noreturn;
    ReturnTypes[@enumToInt(ID.thread_exit)][@enumToInt(ExecutionMode.non_blocking)] = void;
    ReturnTypes[@enumToInt(ID.log)][@enumToInt(ExecutionMode.blocking)] = void;
    ReturnTypes[@enumToInt(ID.log)][@enumToInt(ExecutionMode.non_blocking)] = void;
    ReturnTypes[@enumToInt(ID.read_file)][@enumToInt(ExecutionMode.blocking)] = []const u8;
    ReturnTypes[@enumToInt(ID.read_file)][@enumToInt(ExecutionMode.non_blocking)] = void;
    ReturnTypes[@enumToInt(ID.allocate_memory)][@enumToInt(ExecutionMode.blocking)] = []u8;
    ReturnTypes[@enumToInt(ID.allocate_memory)][@enumToInt(ExecutionMode.non_blocking)] = void;
    break :blk ReturnTypes;
};

const SyscallParameters = blk: {
    var ParameterTypes: [ID.count]type = undefined;
    ParameterTypes[@enumToInt(ID.thread_exit)] = ThreadExitParameters;
    ParameterTypes[@enumToInt(ID.log)] = LogParameters;
    ParameterTypes[@enumToInt(ID.read_file)] = ReadFileParameters;
    ParameterTypes[@enumToInt(ID.allocate_memory)] = AllocateMemoryParameters;
    break :blk ParameterTypes;
};

pub const Submission = struct {
    input: Input,
    arguments: [5]u64,

    comptime {
        common.comptime_assert(@sizeOf(Submission) == 6 * @sizeOf(u64));
    }
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

    pub fn syscall(manager: *Manager, comptime id: ID, comptime execution_mode: ExecutionMode, parameters: SyscallParameters[@enumToInt(id)]) SyscallReturnType[@enumToInt(id)][@enumToInt(execution_mode)] {
        const ReturnType = SyscallReturnType[@enumToInt(id)][@enumToInt(execution_mode)];
        const submission = switch (id) {
            .thread_exit => thread_exit(parameters),
            .log => log(parameters),
            .read_file => read_file(parameters),
            .allocate_memory => allocate_memory(parameters),
        };

        switch (execution_mode) {
            .blocking => {
                const result = immediate_syscall(submission);
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
                        else => common.panic(@src(), "NI: {}", .{id}),
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
        common.runtime_assert(@src(), manager.completion_queue.head == submission_queue_head);
    }
};

const SyscallDescriptor = struct {};

pub const SyscallID = enum(Input.IDIntType) {
    ask_syscall_manager = 0,
    flush_syscall_manager = 1,

    pub const count = common.enum_count(@This());
};

pub fn add_syscall_descriptor(comptime id: SyscallID, arr: []SyscallDescriptor) void {
    _ = arr;
    _ = id;
}

pub const ServiceID = enum(Input.IDIntType) {
    thread_exit = 0,
    log = 1,
    read_file = 2,
    allocate_memory = 3,

    pub const count = common.enum_count(@This());
};

const ServiceDescriptor = struct {
    id: ID,
    UserParameters: type,
    UserResult: type,
    used: bool = false,
};

pub fn add_service_descriptor(comptime id: ID, arr: []ServiceDescriptor) void {
    _ = id;
    _ = arr;
}

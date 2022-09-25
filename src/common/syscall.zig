const std = @import("std.zig");
comptime {
    if (@import("builtin").os.tag != .freestanding) @compileError("This file should not be imported in build.zig");
}

pub const RawResult = extern struct {
    a: u64,
    b: u64,
};

pub const Options = packed struct(u8) {
    execution_mode: ExecutionMode,
    type: Type,
    unused: u6 = 0,

    comptime {
        std.assert(@bitSizeOf(Options) == @bitSizeOf(u8));
    }
};

pub const Input = extern struct {
    const IDIntType = u16;
    id: IDIntType,
    options: Options,
    unused0: u8 = 0,
    unused1: u16 = 0,
    unused2: u16 = 0,

    comptime {
        std.assert(@sizeOf(Input) == @sizeOf(u64));
    }
};

pub const Type = enum(u1) {
    hardware = 0,
    software = 1,
};

pub const HardwareID = enum(u16) {
    ask_syscall_manager = 0,
    flush_syscall_manager = 1,

    pub const count = std.enum_count(@This());
};

pub const ThreadExitParameters = struct {
    message: ?[]const u8 = null,
    exit_code: u64 = 0,
};

pub const LogParameters = struct {
    message: []const u8,
};
pub const ReadFileParameters = struct {
    name: []const u8,
};

pub const AllocateMemoryParameters = struct {
    size: u64,
    alignment: u64,
};

pub const GetFramebufferParameters = void;

pub const ExecutionMode = enum(u1) {
    blocking,
    non_blocking,
    const count = std.enum_count(@This());
};

pub const SyscallReturnType = blk: {
    var ReturnTypes: [ServiceID.count][ExecutionMode.count]type = undefined;
    ReturnTypes[@enumToInt(ServiceID.thread_exit)][@enumToInt(ExecutionMode.blocking)] = noreturn;
    ReturnTypes[@enumToInt(ServiceID.thread_exit)][@enumToInt(ExecutionMode.non_blocking)] = void;
    ReturnTypes[@enumToInt(ServiceID.log)][@enumToInt(ExecutionMode.blocking)] = void;
    ReturnTypes[@enumToInt(ServiceID.log)][@enumToInt(ExecutionMode.non_blocking)] = void;
    ReturnTypes[@enumToInt(ServiceID.read_file)][@enumToInt(ExecutionMode.blocking)] = []const u8;
    ReturnTypes[@enumToInt(ServiceID.read_file)][@enumToInt(ExecutionMode.non_blocking)] = void;
    ReturnTypes[@enumToInt(ServiceID.allocate_memory)][@enumToInt(ExecutionMode.blocking)] = []u8;
    ReturnTypes[@enumToInt(ServiceID.allocate_memory)][@enumToInt(ExecutionMode.non_blocking)] = void;
    ReturnTypes[@enumToInt(ServiceID.get_framebuffer)][@enumToInt(ExecutionMode.blocking)] = *Framebuffer;
    ReturnTypes[@enumToInt(ServiceID.get_framebuffer)][@enumToInt(ExecutionMode.non_blocking)] = void;
    break :blk ReturnTypes;
};

pub const SyscallParameters = blk: {
    var ParameterTypes: [ServiceID.count]type = undefined;
    ParameterTypes[@enumToInt(ServiceID.thread_exit)] = ThreadExitParameters;
    ParameterTypes[@enumToInt(ServiceID.log)] = LogParameters;
    ParameterTypes[@enumToInt(ServiceID.read_file)] = ReadFileParameters;
    ParameterTypes[@enumToInt(ServiceID.allocate_memory)] = AllocateMemoryParameters;
    ParameterTypes[@enumToInt(ServiceID.get_framebuffer)] = GetFramebufferParameters;
    break :blk ParameterTypes;
};

pub const Submission = struct {
    input: Input,
    arguments: [5]u64,

    comptime {
        std.assert(@sizeOf(Submission) == 6 * @sizeOf(u64));
    }
};

pub const Completion = RawResult;

pub const QueueDescriptor = struct {
    head: u32,
    tail: u32,
    offset: u32,
};

pub const Manager = struct {
    buffer: []u8,
    submission_queue: QueueDescriptor,
    completion_queue: QueueDescriptor,
};

//pub const KernelManager = struct {
//kernel: ?*Manager,
//user: ?*Manager,
//};

// TODO: develop on this idea
const SyscallDescriptor = struct {};

pub const SyscallID = enum(Input.IDIntType) {
    ask_syscall_manager = 0,
    flush_syscall_manager = 1,

    pub const count = std.enum_count(@This());
};

pub const ServiceID = enum(Input.IDIntType) {
    thread_exit = 0,
    log = 1,
    read_file = 2,
    allocate_memory = 3,
    get_framebuffer = 4,

    pub const count = std.enum_count(@This());
};

pub fn add_syscall_descriptor(comptime id: SyscallID, arr: []SyscallDescriptor) void {
    _ = arr;
    _ = id;
}

const ServiceDescriptor = struct {
    id: ServiceID,
    UserParameters: type,
    UserResult: type,
    used: bool = false,
};

pub fn add_service_descriptor(comptime id: ServiceID, arr: []ServiceDescriptor) void {
    _ = id;
    _ = arr;
}

const lib = @import("lib");
const assert = lib.assert;

const rise = @import("rise");
const syscall = rise.syscall;

const Capabilities = @This();

pub const Type = enum(u8) {
    io, // primitive
    cpu, // primitive
    ram, // primitive
    cpu_memory, // non-primitive
    // TODO: device_memory, // primitive
    // vnode,
    // scheduler,
    // irq_table,

    // _,

    pub const Type = u8;
};

pub const Subtype = u16;
pub const AllTypes = Type;

pub fn CommandBuilder(comptime list: []const []const u8) type {
    const capability_base_command_list = .{
        "copy",
        "mint",
        "retype",
        "delete",
        "revoke",
        "create",
    } ++ list;
    const enum_fields = lib.enumAddNames(&.{}, capability_base_command_list);

    // TODO: make this non-exhaustive enums
    // PROBLEM: https://github.com/ziglang/zig/issues/12250
    // Currently waiting on this since this will enable some comptime magic
    const result = @Type(.{
        .Enum = .{
            .tag_type = Subtype,
            .fields = enum_fields,
            .decls = &.{},
            .is_exhaustive = true,
        },
    });
    return result;
}

/// Takes some names and integers. Then values are added to the Command enum for an specific capability
/// The number is an offset of the fields with respect to the base command enum fields
pub fn Command(comptime capability: Type) type {
    const extra_command_list = switch (capability) {
        .io => .{
            "log",
        },
        .cpu => .{
            "get_core_id",
            "shutdown",
        },
        .ram => [_][]const u8{},
        .cpu_memory => [_][]const u8{},
    };

    return CommandBuilder(&extra_command_list);
}

pub fn ErrorSet(comptime error_list: anytype) type {
    return lib.ErrorSet(error_list, &.{
        .{
            .name = "ok",
            .value = 0,
        },
        .{
            .name = "forbidden",
            .value = 1,
        },
        .{
            .name = "corrupted_input",
            .value = 2,
        },
        .{
            .name = "invalid_input",
            .value = 3,
        },
    });
}

const raw_argument_count = @typeInfo(syscall.Arguments).Array.len;
const zero_arguments = [1]usize{0} ** raw_argument_count;

pub fn Syscall(comptime capability_type: Type, comptime command_type: Command(capability_type)) type {
    const Types = switch (capability_type) {
        .io => switch (command_type) {
            .copy, .mint, .retype, .delete, .revoke, .create => struct {
                pub const ErrorSet = Capabilities.ErrorSet(.{});
                pub const Result = void;
                pub const Arguments = void;
            },
            .log => struct {
                pub const ErrorSet = Capabilities.ErrorSet(.{});
                pub const Result = usize;
                pub const Arguments = []const u8;

                pub inline fn toResult(raw_result: syscall.Result.Rise) Result {
                    return raw_result.second;
                }

                pub inline fn resultToRaw(result: Result) syscall.Result {
                    return syscall.Result{
                        .rise = .{
                            .first = .{},
                            .second = result,
                        },
                    };
                }

                inline fn argumentsToRaw(arguments: Arguments) syscall.Arguments {
                    const result = [2]usize{ @ptrToInt(arguments.ptr), arguments.len };
                    return result ++ .{0} ** (raw_argument_count - result.len);
                }

                inline fn toArguments(raw_arguments: syscall.Arguments) !Arguments {
                    const message_ptr = @intToPtr(?[*]const u8, raw_arguments[0]) orelse return error.invalid_input;
                    const message_len = raw_arguments[1];
                    if (message_len == 0) return error.invalid_input;
                    const message = message_ptr[0..message_len];
                    return message;
                }
            },
        },
        .cpu => switch (command_type) {
            .copy, .mint, .retype, .delete, .revoke, .create => struct {
                pub const ErrorSet = Capabilities.ErrorSet(.{});
                pub const Result = void;
                pub const Arguments = void;
            },
            .get_core_id => struct {
                pub const ErrorSet = Capabilities.ErrorSet(.{});
                pub const Result = u32;
                pub const Arguments = void;

                pub inline fn toResult(raw_result: syscall.Result.Rise) Result {
                    return @intCast(Result, raw_result.second);
                }

                pub inline fn resultToRaw(result: Result) syscall.Result {
                    return syscall.Result{
                        .rise = .{
                            .first = .{},
                            .second = result,
                        },
                    };
                }
            },
            .shutdown => struct {
                pub const ErrorSet = Capabilities.ErrorSet(.{});
                pub const Result = noreturn;
                pub const Arguments = void;

                pub const toResult = @compileError("noreturn unexpectedly returned");
            },
        },
        .ram, .cpu_memory => struct {
            pub const ErrorSet = Capabilities.ErrorSet(.{});
            pub const Result = void;
            pub const Arguments = void;
        },
        // else => @compileError("TODO: " ++ @tagName(capability)),
    };

    return struct {
        pub const ErrorSet = Types.ErrorSet;
        pub const Result = Types.Result;
        pub const Arguments = Types.Arguments;
        pub const toResult = Types.toResult;
        pub const toArguments = if (@hasDecl(Types, "toArguments")) Types.toArguments else struct {
            fn lambda(raw_arguments: syscall.Arguments) error{}!void {
                _ = raw_arguments;
                return {};
            }
        }.lambda;
        pub const capability = capability_type;
        pub const command = command_type;

        pub inline fn resultToRaw(result: Result) syscall.Result {
            return if (@hasDecl(Types, "resultToRaw")) blk: {
                comptime assert(Result != void and Result != noreturn);
                break :blk Types.resultToRaw(result);
            } else blk: {
                if (Result != void) {
                    @compileError("expected void type, got " ++ @typeName(Result) ++ ". You forgot to implement a resultToRaw function" ++ " for (" ++ @tagName(capability) ++ ", " ++ @tagName(command) ++ ").");
                }

                break :blk syscall.Result{
                    .rise = .{
                        .first = .{},
                        .second = 0,
                    },
                };
            };
        }

        pub inline fn errorToRaw(err: @This().ErrorSet.Error) syscall.Result {
            const error_enum = switch (err) {
                inline else => |comptime_error| @field(@This().ErrorSet.Enum, @errorName(comptime_error)),
            };
            return syscall.Result{
                .rise = .{
                    .first = .{
                        .@"error" = @enumToInt(error_enum),
                    },
                    .second = 0,
                },
            };
        }

        /// This is not meant to be called in the CPU driver
        pub fn blocking(arguments: Arguments) @This().ErrorSet.Error!Result {
            const raw_arguments = if (@hasDecl(Types, "argumentsToRaw")) Types.argumentsToRaw(arguments) else zero_arguments;
            // TODO: make this more reliable and robust?
            const options = rise.syscall.Options{
                .rise = .{
                    .type = capability,
                    .command = @enumToInt(command),
                },
            };

            const raw_result = rise.arch.syscall(options, raw_arguments);

            const error_value = @intToEnum(@This().ErrorSet.Enum, raw_result.rise.first.@"error");

            return switch (error_value) {
                .ok => switch (Result) {
                    noreturn => unreachable,
                    else => toResult(raw_result.rise),
                },
                inline else => |comptime_error_enum| @field(@This().ErrorSet.Error, @tagName(comptime_error_enum)),
            };
        }
    };
}

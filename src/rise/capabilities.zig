const lib = @import("lib");
const assert = lib.assert;
const PhysicalAddress = lib.PhysicalAddress;

const rise = @import("rise");
const syscall = rise.syscall;

const Capabilities = @This();

pub const Type = enum(u8) {
    io, // primitive
    cpu, // primitive
    ram, // primitive
    cpu_memory, // non-primitive Barrelfish: frame
    boot,
    process, // Temporarily available
    page_table, // Barrelfish: vnode
    // TODO: device_memory, // primitive
    // scheduler,
    // irq_table,

    // _,

    pub const Type = u8;

    pub const Mappable = enum {
        cpu_memory,
        page_table,

        pub inline fn toCapability(mappable: Mappable) Capabilities.Type {
            return switch (mappable) {
                inline else => |mappable_cap| @field(Capabilities.Type, @tagName(mappable_cap)),
            };
        }
    };
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
            "get_command_buffer",
        },
        .ram => [_][]const u8{},
        .cpu_memory => .{
            "allocate",
        },
        .boot => .{
            "get_bundle_size",
            "get_bundle_file_list_size",
        },
        .process => .{
            "exit",
        },
        .page_table => [_][]const u8{},
    };

    return CommandBuilder(&extra_command_list);
}

const success = 0;
const first_valid_error = success + 1;

pub fn ErrorSet(comptime error_names: []const []const u8) type {
    return lib.ErrorSet(error_names, &.{
        .{
            .name = "forbidden",
            .value = first_valid_error + 0,
        },
        .{
            .name = "corrupted_input",
            .value = first_valid_error + 1,
        },
        .{
            .name = "invalid_input",
            .value = first_valid_error + 2,
        },
    });
}

const raw_argument_count = @typeInfo(syscall.Arguments).Array.len;

pub fn Syscall(comptime capability_type: Type, comptime command_type: Command(capability_type)) type {
    const Types = switch (capability_type) {
        .io => switch (command_type) {
            .copy, .mint, .retype, .delete, .revoke, .create => struct {
                pub const ErrorSet = Capabilities.ErrorSet(&.{});
                pub const Result = void;
                pub const Arguments = void;
            },
            .log => struct {
                pub const ErrorSet = Capabilities.ErrorSet(&.{});
                pub const Result = usize;
                pub const Arguments = []const u8;

                inline fn toResult(raw_result: syscall.Result.Rise) Result {
                    return raw_result.second;
                }

                inline fn resultToRaw(result: Result) syscall.Result {
                    return syscall.Result{
                        .rise = .{
                            .first = .{},
                            .second = result,
                        },
                    };
                }

                inline fn argumentsToRaw(arguments: Arguments) syscall.Arguments {
                    const result = [2]usize{ @intFromPtr(arguments.ptr), arguments.len };
                    return result ++ .{0} ** (raw_argument_count - result.len);
                }

                inline fn toArguments(raw_arguments: syscall.Arguments) !Arguments {
                    const message_ptr = @as(?[*]const u8, @ptrFromInt(raw_arguments[0])) orelse return error.invalid_input;
                    const message_len = raw_arguments[1];
                    if (message_len == 0) return error.invalid_input;
                    const message = message_ptr[0..message_len];
                    return message;
                }
            },
        },
        .cpu => switch (command_type) {
            .copy, .mint, .retype, .delete, .revoke, .create => struct {
                pub const ErrorSet = Capabilities.ErrorSet(&.{});
                pub const Result = void;
                pub const Arguments = void;
            },
            .get_core_id => struct {
                pub const ErrorSet = Capabilities.ErrorSet(&.{});
                pub const Result = u32;
                pub const Arguments = void;

                inline fn toResult(raw_result: syscall.Result.Rise) Result {
                    return @as(Result, @intCast(raw_result.second));
                }

                inline fn resultToRaw(result: Result) syscall.Result {
                    return syscall.Result{
                        .rise = .{
                            .first = .{},
                            .second = result,
                        },
                    };
                }
            },
            .shutdown => struct {
                pub const ErrorSet = Capabilities.ErrorSet(&.{});
                pub const Result = noreturn;
                pub const Arguments = void;

                pub const toResult = @compileError("noreturn unexpectedly returned");
            },
            .get_command_buffer => struct {
                pub const ErrorSet = Capabilities.ErrorSet(&.{});
                pub const Result = noreturn;
                pub const Arguments = *rise.CommandBuffer;

                pub const toResult = @compileError("noreturn unexpectedly returned");

                inline fn toArguments(raw_arguments: syscall.Arguments) !Arguments {
                    const ptr = @as(?*rise.CommandBuffer, @ptrFromInt(raw_arguments[0])) orelse return error.invalid_input;
                    return ptr;
                }

                inline fn argumentsToRaw(arguments: Arguments) syscall.Arguments {
                    const result = [1]usize{@intFromPtr(arguments)};
                    return result ++ .{0} ** (raw_argument_count - result.len);
                }
            },
        },
        .ram => struct {
            pub const ErrorSet = Capabilities.ErrorSet(&.{});
            pub const Result = void;
            pub const Arguments = void;
        },
        .cpu_memory => struct {
            pub const ErrorSet = Capabilities.ErrorSet(&.{
                "OutOfMemory",
            });
            pub const Result = PhysicalAddress;
            pub const Arguments = usize;

            inline fn toResult(raw_result: syscall.Result.Rise) Result {
                return PhysicalAddress.new(raw_result.second);
            }

            inline fn resultToRaw(result: Result) syscall.Result {
                return syscall.Result{
                    .rise = .{
                        .first = .{},
                        .second = result.value(),
                    },
                };
            }

            inline fn toArguments(raw_arguments: syscall.Arguments) !Arguments {
                const size = raw_arguments[0];
                return size;
            }

            inline fn argumentsToRaw(arguments: Arguments) syscall.Arguments {
                const result = [1]usize{arguments};
                return result ++ .{0} ** (raw_argument_count - result.len);
            }
        },
        .boot => switch (command_type) {
            .get_bundle_file_list_size, .get_bundle_size => struct {
                pub const ErrorSet = Capabilities.ErrorSet(&.{
                    "buffer_too_small",
                });
                pub const Result = usize;
                pub const Arguments = void;

                inline fn resultToRaw(result: Result) syscall.Result {
                    return syscall.Result{
                        .rise = .{
                            .first = .{},
                            .second = result,
                        },
                    };
                }

                inline fn toResult(raw_result: syscall.Result.Rise) Result {
                    return raw_result.second;
                }
            },
            else => struct {
                pub const ErrorSet = Capabilities.ErrorSet(&.{
                    "buffer_too_small",
                });
                pub const Result = void;
                pub const Arguments = void;
            },
        },
        .process => switch (command_type) {
            .exit => struct {
                pub const ErrorSet = Capabilities.ErrorSet(&.{});
                pub const Result = noreturn;
                pub const Arguments = bool;

                inline fn toArguments(raw_arguments: syscall.Arguments) !Arguments {
                    const result = raw_arguments[0] != 0;
                    return result;
                }
                inline fn argumentsToRaw(arguments: Arguments) syscall.Arguments {
                    const result = [1]usize{@intFromBool(arguments)};
                    return result ++ .{0} ** (raw_argument_count - result.len);
                }
            },
            else => struct {
                pub const ErrorSet = Capabilities.ErrorSet(&.{});
                pub const Result = void;
                pub const Arguments = void;
            },
        },
        .page_table => switch (command_type) {
            else => struct {
                pub const ErrorSet = Capabilities.ErrorSet(&.{});
                pub const Result = void;
                pub const Arguments = void;
            },
        },
        // else => @compileError("TODO: " ++ @tagName(capability)),
    };

    return struct {
        pub const ErrorSet = Types.ErrorSet;
        pub const Result = Types.Result;
        pub const Arguments = Types.Arguments;
        pub const toResult = Types.toResult;
        pub const toArguments = if (Arguments != void)
            Types.toArguments
        else
            struct {
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
                        .@"error" = @intFromEnum(error_enum),
                    },
                    .second = 0,
                },
            };
        }

        /// This is not meant to be called in the CPU driver
        pub fn blocking(arguments: Arguments) @This().ErrorSet.Error!Result {
            const raw_arguments = if (Arguments != void) Types.argumentsToRaw(arguments) else [1]usize{0} ** raw_argument_count;
            // TODO: make this more reliable and robust?
            const options = rise.syscall.Options{
                .rise = .{
                    .type = capability,
                    .command = @intFromEnum(command),
                },
            };

            const raw_result = rise.arch.syscall(options, raw_arguments);

            const raw_error_value = raw_result.rise.first.@"error";
            comptime {
                assert(!@hasField(@This().ErrorSet.Enum, "ok"));
                assert(!@hasField(@This().ErrorSet.Enum, "success"));
                assert(lib.enumFields(@This().ErrorSet.Enum)[0].value == first_valid_error);
            }

            return switch (raw_error_value) {
                success => switch (Result) {
                    noreturn => unreachable,
                    else => toResult(raw_result.rise),
                },
                else => switch (@as(@This().ErrorSet.Enum, @enumFromInt(raw_error_value))) {
                    inline else => |comptime_error_enum| @field(@This().ErrorSet.Error, @tagName(comptime_error_enum)),
                },
            };
        }
    };
}

const std = @import("std.zig");

const SafeFunctionCastError = error{
    destination_function_type_not_a_function,
    source_function_type_not_a_function,
    calling_convention_mismatch,
    alignment_mismatch,
    is_generic_mismatch,
    is_var_args_mismatch,
    return_type_mismatch,
    argument_type_mismatch,
};

const TypeMatch = enum {
    ignore,
    size,
    type,
};

pub const SafeFunctionCastParameters = struct {
    FunctionType: type,
    match_argument_types: TypeMatch = .type,
    match_return_type: TypeMatch = .type,
    match_calling_convention: bool = true,
};

pub fn safe_function_cast(function: anytype, comptime parameters: SafeFunctionCastParameters) SafeFunctionCastError!parameters.FunctionType {
    if (std.is_comptime()) {
        const destination_type_info = @typeInfo(parameters.FunctionType);
        if (destination_type_info != .Fn) return SafeFunctionCastError.destination_function_type_not_a_function;
        const SourceFunctionType = @TypeOf(function);
        const source_type_info = @typeInfo(SourceFunctionType);
        if (source_type_info != .Fn) return SafeFunctionCastError.source_function_type_not_a_function;
        const source_function_type = source_type_info.Fn;
        const destination_function_type = destination_type_info.Fn;
        if (source_function_type.calling_convention != destination_function_type.calling_convention) return SafeFunctionCastError.calling_convention_mismatch;
        if (source_function_type.alignment != destination_function_type.alignment) return SafeFunctionCastError.alignment_mismatch;
        if (source_function_type.is_generic != destination_function_type.is_generic) return SafeFunctionCastError.is_generic_mismatch;
        if (source_function_type.is_var_args != destination_function_type.is_var_args) return SafeFunctionCastError.is_var_args_mismatch;

        if (parameters.match_return_type != .ignore) {
            if (!(source_function_type.return_type == null and destination_function_type.return_type == null)) {
                const source_type = source_function_type.return_type orelse return SafeFunctionCastError.return_type_mismatch;
                const destination_type = destination_function_type.return_type orelse return SafeFunctionCastError.return_type_mismatch;

                switch (parameters.match_return_type) {
                    .ignore => unreachable,
                    .size => {
                        if (source_type != destination_type) {
                            const source_bit_size = @bitSizeOf(source_function_type.return_type);
                            const destination_bit_size = @bitSizeOf(destination_function_type.return_type);
                            if (source_bit_size != destination_bit_size) return SafeFunctionCastError.return_type_mismatch;
                        }
                    },
                    .type => {
                        if (source_type != destination_type) return SafeFunctionCastError.return_type_mismatch;
                    },
                }
            }
        }

        for (source_function_type.args) |source_argument, arg_i| {
            const destination_argument = destination_function_type.args[arg_i];
            if (source_argument.is_generic != destination_argument.is_generic) return SafeFunctionCastError.argument_type_mismatch;
            if (source_argument.is_noalias != destination_argument.is_noalias) return SafeFunctionCastError.argument_type_mismatch;
            if (parameters.match_argument_types != .ignore) {
                if (!(source_argument.arg_type == null and destination_argument.arg_type == null)) {
                    const source_type = source_argument.arg_type orelse return SafeFunctionCastError.argument_type_mismatch;
                    const destination_type = destination_argument.arg_type orelse return SafeFunctionCastError.argument_type_mismatch;
                    switch (parameters.match_argument_types) {
                        .ignore => unreachable,
                        .size => {
                            if (source_type != destination_type) {
                                const source_bit_size = @bitSizeOf(source_type);
                                const destination_bit_size = @bitSizeOf(destination_type);
                                if (source_bit_size != destination_bit_size) return SafeFunctionCastError.argument_type_mismatch;
                            }
                        },
                        .type => {
                            if (source_type != destination_type) {
                                return SafeFunctionCastError.argument_type_mismatch;
                            }
                        },
                    }
                }
            }
        }

        return @ptrCast(parameters.FunctionType, function);
    } else {
        @panic("safe_fn_cast");
    }
}

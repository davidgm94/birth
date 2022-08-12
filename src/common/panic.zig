const root = @import("root");
const std = @import("std.zig");

pub fn TODO(src: std.SourceLocation) noreturn {
    if (@hasDecl(root, "identity")) {
        root.crash("TODO at {s}:{}:{} {s}()", .{ src.file, src.line, src.column, src.fn_name });
    } else {
        std.log.err("PANIC at {s}:{}:{} {s}()", .{ src.file, src.line, src.column, src.fn_name });
        unreachable;
    }
}

pub fn panic(src: std.SourceLocation, comptime message: []const u8, args: anytype) noreturn {
    if (@hasDecl(root, "identity")) {
        root.crash(message, args);
    } else {
        std.log.err("PANIC at {s}:{}:{} {s}()", .{ src.file, src.line, src.column, src.fn_name });
        unreachable;
    }
}

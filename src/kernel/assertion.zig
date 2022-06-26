const kernel = @import("kernel");

pub fn assert_unsafe(condition: bool) void {
    if (!condition) unreachable;
}

pub fn assert(src: kernel.SourceLocation, condition: bool) void {
    if (!condition) kernel.panic("Assert failed at {s}:{}:{} {s}()\n", .{ src.file, src.line, src.column, src.fn_name });
}

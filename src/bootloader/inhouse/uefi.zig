const std = @import("std");
const uefi = std.os.uefi;
const str16 = std.unicode.utf8ToUtf16LeStringLiteral;

pub fn main() noreturn {
    const out = uefi.system_table.con_out orelse unreachable;
    _ = out.reset(true);
    _ = out.clearScreen();
    _ = out.outputString(str16("Hello world\n"));

    asm volatile (
        \\cli
        \\hlt
    );
    unreachable;
}

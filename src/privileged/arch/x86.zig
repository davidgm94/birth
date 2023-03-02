const lib = @import("lib");
const assert = lib.assert;
const privileged = @import("privileged");

const x86 = @import("x86/common.zig");
pub usingnamespace x86;

pub const io = @import("x86/32/io.zig");

/// Use x86_64 paging for VirtualAddressSpace
pub const paging = privileged.arch.x86_64.paging;

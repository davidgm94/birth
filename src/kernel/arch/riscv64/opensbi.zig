//! SBI wrapper

const std = @import("std");

/// 2.Binray Encoding
/// According to SBI doc
pub const SBI_RET = struct {
    err: i64,
    val: i64,
};

/// Doing a SBI ecall
inline fn sbi_call(
    eid: i32,
    fid: i32,
    arg0: usize,
    arg1: usize,
    arg2: usize,
) SBI_RET {
    var err: c_long = 0;
    var val: c_long = 0;

    asm volatile ("ecall"
        : [ret] "={x10}" (err), // err a0
          [val] "={x11}" (val) // err a0
        : [eid] "{x17}" (eid), // a7 for EID
          [fid] "{x16}" (fid), // a6 for FID
          [arg0] "{x10}" (arg0),
          [arg1] "{x11}" (arg1),
          [arg2] "{x12}" (arg2)
        : "memory"
    );

    return SBI_RET{
        .err = err,
        .val = val,
    };
}

/// 5. Timer Extension (EID #0x54494D45 "TIME")
/// Available since SBI v0.2
const TIME_EID: i32 = 0x54494D45;
const TIME_SET_TIMER_FID: i32 = 0x0;

/// set next clock interrupt
/// not expecting any error
pub fn set_timer(time: u64) void {
    _ = sbi_call(TIME_EID, TIME_SET_TIMER_FID, time, 0, 0);
}

/// 9. System Reset Extension (EID #0x53525354 "SRST")
/// SRST Extension is in SBI v0.3, so OpenSBI v0.9 and above is required
/// For running in QEMU, QEMU 6.0.0 and above is required
const SRST_EID: i32 = 0x53525354;
const SRST_SYSTEM_RESET_FID: i32 = 0x0;

const SRST_SYSTEM_RESET_TYPE = enum(u32) {
    SHUTDOWN = 0x00000000,
    COLD_REBOOT = 0x00000001,
    WARM_REBOOT = 0x00000002,
};

const SRST_SYSTEM_RESET_REASON = enum(u32) {
    NO_REASON = 0x00000000,
    SYSTEM_FAILURE = 0x00000001,
};

pub fn system_reset(reset_type: SRST_SYSTEM_RESET_TYPE, reset_reason: SRST_SYSTEM_RESET_REASON) SBI_RET {
    return sbi_call(SRST_EID, SRST_SYSTEM_RESET_FID, reset_type, reset_reason, 0);
}

/// Shutdown all system
pub fn shutdown() noreturn {
    _ = sbi_call(SRST_EID, SRST_SYSTEM_RESET_FID, @enumToInt(SRST_SYSTEM_RESET_TYPE.SHUTDOWN), @enumToInt(SRST_SYSTEM_RESET_REASON.NO_REASON), 0);
    while (true) {} // Make Zig compiler happy
}

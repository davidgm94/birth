const lib = @import("lib");
const assert = lib.assert;
const log = lib.log.scoped(.Syscall_x86_64);

const privileged = @import("privileged");
const x86_64 = privileged.arch.x86_64;
const GDT = x86_64.GDT;
const IA32_STAR = x86_64.registers.IA32_STAR;
const IA32_LSTAR = x86_64.registers.IA32_LSTAR;
const IA32_EFER = x86_64.registers.IA32_EFER;
const IA32_FMASK = x86_64.registers.IA32_FMASK;

pub fn enable(kernel_syscall_entry_point: u64) void {
    // Set selectors into the IA32_STAR MSR
    const star = IA32_STAR{
        .kernel_cs = @offsetOf(GDT.Table, "code_64"),
        .user_cs_anchor = @offsetOf(GDT.Table, "data_64"),
    };
    comptime {
        assert(@offsetOf(GDT.Table, "data_64") == star.kernel_cs + 8);
        assert(star.user_cs_anchor == @offsetOf(GDT.Table, "user_data_64") - 8);
        assert(star.user_cs_anchor == @offsetOf(GDT.Table, "user_code_64") - 16);
    }

    star.write();

    IA32_LSTAR.write(@ptrToInt(&kernel_syscall_entry_point));
    // TODO: figure out what this does
    IA32_FMASK.write(@truncate(u22, ~@as(u64, 1 << 1)));

    // Enable syscall extensions
    var efer = IA32_EFER.read();
    efer.SCE = true;
    IA32_EFER.write(efer);

    log.debug("Enabled syscalls", .{});
}

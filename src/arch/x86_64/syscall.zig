const common = @import("common");
const assert = common.assert;
const log = common.log.scoped(.Syscall_x86_64);

const rise = @import("rise");
const Thread = rise.Thread;
const Syscall = rise.Syscall;

const arch = @import("arch");
const x86_64 = arch.x86_64;
const GDT = x86_64.GDT;
const registers = x86_64.registers;

pub fn enable(kernel_syscall_entry_point: u64) void {
    // Set selectors into the IA32_STAR MSR
    const star = registers.IA32_STAR{
        .kernel_cs = @offsetOf(GDT.Table, "code_64"),
        .user_cs_anchor = @offsetOf(GDT.Table, "data_64"),
    };
    comptime {
        assert(@offsetOf(GDT.Table, "data_64") == star.kernel_cs + 8);
        assert(star.user_cs_anchor == @offsetOf(GDT.Table, "user_data_64") - 8);
        assert(star.user_cs_anchor == @offsetOf(GDT.Table, "user_code_64") - 16);
    }

    star.write();

    registers.IA32_LSTAR.write(@ptrToInt(&kernel_syscall_entry_point));
    // TODO: figure out what this does
    registers.IA32_FMASK.write(@truncate(u22, ~@as(u64, 1 << 1)));

    // Enable syscall extensions
    var efer = registers.IA32_EFER.read();
    efer.SCE = true;
    registers.IA32_EFER.write(efer);

    log.debug("Enabled syscalls", .{});
}

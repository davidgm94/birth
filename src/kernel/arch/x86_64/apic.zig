const common = @import("common");
const log = common.log.scoped(.APIC);

const privileged = @import("privileged");
const arch = @import("arch");
const get_apic_base = arch.x86_64.registers.get_apic_base;

pub fn init() void {
    const apic_base = get_apic_base();
    log.debug("APIC base: {}", .{apic_base});
    arch.paging.map_device(apic_base, arch.page_size) catch @panic("mapping apic failed");
    @panic("todo apic");
}

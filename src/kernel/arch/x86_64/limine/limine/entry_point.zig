const Limine = @import("limine.zig");

export var hhdm = Limine.HHDM.Request{
    .revision = 0,
};

pub export fn kernel_entry_point() noreturn {
    const hhdm_slide: u64 = if (hhdm.response) |response| response.offset else 0;
    var hhdm_value = hhdm_slide;
    _ = hhdm_value;
    while (true) {}
}

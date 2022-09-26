const std = @import("../common/std.zig");

const kernel = @import("kernel.zig");
const TLS = @import("arch/tls.zig");
const Timer = @import("timer.zig");

const log = std.log.scoped(.Main);

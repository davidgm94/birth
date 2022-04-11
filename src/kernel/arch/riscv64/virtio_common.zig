pub const MMIO = packed struct {
    magic_value: u32,
    version: u32,
    device_id: u32,
    vendor_id: u32,

    device_features: u32,
    device_feature_selector: u32,
    reserved1: [8]u8,

    driver_features: u32,
    driver_feature_selector: u32,
    reserved2: [8]u8,

    queue_selector: u32,
    queue_num_max: u32,
    queue_num: u32,
    reserved3: [4]u8,

    reserved4: [4]u8,
    queue_ready: u32,
    reserved5: [8]u8,

    queue_notify: u32,
    reserved6: [12]u8,
    
    interrupt_status: u32,
    interrupt_ack: u32,
    reserved7: [8]u8,

    status: u32,
    reserved8: [12]u8,

    queue_descriptor_low: u32,
    queue_descriptor_high: u32,
    reserved9: [8]u8,

    queue_available_low: u32,
    queue_available_high: u32,
    reserved10: [8]u8,

    queue_used_low: u32,
    queue_used_high: u32,
    reserved11: [8]u8,

    reserved12: [0x4c]u8,
    config_gen: u32,

    const magic = 0x74726976;
    const version = 2;

    pub fn init(self: *volatile @This()) void {
        if (self.magic_value != magic) @panic("virtio magic corrupted");
        if (self.version != version) @panic("outdated virtio spec");
        if (self.device_id == 0) @panic("invalid device");

        const device_id = self.device_id;

        // 1. Reset
        self.status = 0;

        // 2. Ack the device
        self.status |= @enumToInt(Status.acknowledge);

        // 3. The driver knows how to use the device
        self.status |= @enumToInt(Status.driver);

        // 4. Read device feature bits and write (a subset of) them
        var features = self.device_features;
        // Disable VIRTIO F RING EVENT INDEX
        features &= ~(1 << 29);
        self.driver_features = features;

        // 5. Set features ok status bit
        self.status |= @enumToInt(Status.features_ok);

        if (self.status & @enumToInt(Status.features_ok) == 0) @panic("unsupported features");
    }

    const Status = enum(u32) {
        acknowledge = 1 << 0,
        driver = 1 << 1,
        features_ok = 1 << 7,
    };
};

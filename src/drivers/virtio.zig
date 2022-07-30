const common = @import("../common.zig");

const log = common.log.scoped(.Virtio);
const TODO = common.TODO;
const PCI = @import("pci.zig");
pub const Block = @import("virtio/block.zig");

pub const PCIDriver = struct {
    configuration: *volatile CommonConfiguration,
    //notify: [*]volatile Descriptor,
    //notify_mul: u32,
    isr: *volatile u32,
    dev: [*]volatile u8,
    //queues: [16]VirtQueue = undefined,

    pub const vendor_id = 0x1af4;

    pub const TransitionalDeviceID = enum(u16) {
        network_card = 0x1000,
        block_device = 0x1001,
        memory_ballooning = 0x1002,
        console = 0x1003,
        SCSI_host = 0x1004,
        entropy_source = 0x1005,
        transport_9p = 0x1009,
    };

    pub fn detect_bars(device: *PCI.Device) PCIDriver {
        const header_type = device.read_config(u8, PCI.CommonHeader.get_offset("header_type"));
        common.runtime_assert(@src(), header_type == 0);
        const capabilities_pointer = device.read_config(u8, PCI.HeaderType0x00.get_offset("capabilities_pointer")) & 0xfc;
        log.debug("CP: {}", .{capabilities_pointer});
        var capabilities_iterator = CapabilitiesIterator{
            .device = device,
            .offset = capabilities_pointer,
        };

        while (capabilities_iterator.read_next()) |next_cap| {
            const vendor = next_cap.read_vendor();
            log.debug("Vendor: 0x{x}", .{vendor});
            switch (vendor) {
                0x09 => {
                    const configuration_type = next_cap.read_field("configuration_type");
                    const bar = next_cap.read_field("bar");
                    const offset = next_cap.read_field("offset");
                    _ = bar;
                    _ = offset;

                    switch (configuration_type) {
                        .common => {},
                        .notify => {},
                        .isr => {},
                        .device => {},
                        .pci => {},
                    }
                },
                else => {},
            }
        }
        TODO(@src());
    }

    const CapabilitiesIterator = struct {
        device: *PCI.Device,
        offset: u8,

        fn read_next(it: *CapabilitiesIterator) ?CapabilitiesIterator {
            if (it.offset == 0) return null;

            const result = it.*;
            const new_offset = it.read_field("next");
            it.offset = new_offset;
            return result;
        }

        fn read_field(it: CapabilitiesIterator, comptime field_name: []const u8) TypeFromFieldName(field_name) {
            const T = TypeFromFieldName(field_name);
            const field = it.device.read_config(T, it.offset + @offsetOf(Capability, field_name));
            return field;
        }

        fn TypeFromFieldName(comptime field_name: []const u8) type {
            var cap: Capability = undefined;
            return @TypeOf(@field(cap, field_name));
        }

        fn read_vendor(it: CapabilitiesIterator) u8 {
            return it.device.read_config(u8, it.offset);
        }
    };

    pub const Capability = struct {
        vendor: u8,
        next: u8,
        len: u8,
        configuration_type: CapabilityConfigurationType,
        bar: u8,
        padding0: u8,
        padding1: u8,
        padding2: u8,
        offset: u32,
        length: u32,
    };

    pub const CapabilityConfigurationType = enum(u8) {
        common = 1,
        notify = 2,
        isr = 3,
        device = 4,
        pci = 5,
    };

    pub const CommonConfiguration = struct {
        device_features_select: u32,
        device_feature: u32,
        driver_feature_select: u32,
        driver_feature: u32,
        msix_configuration: u16,
        queue_count: u16,
        device_status: u8,
        configuration_generation: u8,

        queue_select: u16,
        queue_size: u16,
        queue_max_size_vector: u16,
        queue_enable: u16,
        queue_notification_offset: u16,
        queue_descriptor: u16,
        queue_driver: u16,
        queue_device: u16,
    };
};

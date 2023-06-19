const lib = @import("lib");
const assert = lib.assert;
const log = lib.log.scoped(.LIMINE);

const bootloader = @import("bootloader");

const limine = @import("limine");

const privileged = @import("privileged");
const ACPI = privileged.ACPI;
const Mapping = privileged.Mapping;
const PageAllocator = privileged.PageAllocator;
const PhysicalAddress = lib.PhysicalAddress;
const PhysicalMemoryRegion = lib.PhysicalMemoryRegion;
const VirtualAddress = lib.VirtualAddress;
const stopCPU = privileged.arch.stopCPU;
const paging = privileged.arch.x86_64.paging;

const writer = privileged.E9Writer{ .context = {} };

const Request = extern struct {
    information: limine.BootloaderInfo.Request = .{ .revision = 0 },
    hhdm: limine.HHDM.Request = .{ .revision = 0 },
    framebuffer: limine.Framebuffer.Request = .{ .revision = 0 },
    smp: limine.SMPInfoRequest = .{ .revision = 0, .flags = .{ .x2apic = false } },
    memory_map: limine.MemoryMap.Request = .{ .revision = 0 },
    modules: limine.Module.Request = .{ .revision = 0 },
    rsdp: limine.RSDP.Request = .{ .revision = 0 },
    smbios: limine.SMBIOS.Request = .{ .revision = 0 },
    efi_system_table: limine.EFISystemTable.Request = .{ .revision = 0 },
    kernel_address: limine.KernelAddress.Request = .{ .revision = 0 },
};

var request = Request{};

comptime {
    @export(request, .{ .linkage = .Strong, .name = "request" });
}

pub fn panic(message: []const u8, _: ?*lib.StackTrace, _: ?usize) noreturn {
    privileged.arch.disableInterrupts();

    writer.writeAll("[PANIC] ") catch {};
    writer.writeAll(message) catch {};
    writer.writeByte('\n') catch {};

    privileged.shutdown(.failure);
}

pub const std_options = struct {
    pub const log_level = lib.std.log.Level.debug;

    pub fn logFn(comptime level: lib.std.log.Level, comptime scope: @TypeOf(.EnumLiteral), comptime format: []const u8, args: anytype) void {
        _ = level;
        // _ = level;
        writer.writeByte('[') catch stopCPU();
        writer.writeAll(@tagName(scope)) catch stopCPU();
        writer.writeAll("] ") catch stopCPU();
        lib.format(writer, format, args) catch stopCPU();
        writer.writeByte('\n') catch stopCPU();
    }
};

const Filesystem = struct {
    modules: []const limine.File,

    pub fn deinitialize(filesystem: *Filesystem) !void {
        _ = filesystem;
    }

    pub fn readFile(filesystem: *Filesystem, file_path: []const u8, file_buffer: []u8) ![]const u8 {
        const module = try filesystem.getModule(file_path);
        assert(file_buffer.len >= module.size);
        @memcpy(file_buffer[0..module.size], module.getContent());
        return file_buffer;
    }

    pub fn sneakFile(filesystem: *Filesystem, file_path: []const u8, size: usize) ![]const u8 {
        _ = size;
        const file = try filesystem.getModule(file_path);
        return file.getContent();
    }

    fn getModule(filesystem: *Filesystem, file_path: []const u8) !*const limine.File {
        for (filesystem.modules) |*module| {
            const path = module.path[0..lib.length(module.path)];
            if (lib.equal(u8, file_path, path)) {
                return module;
            }
        }

        return Error.file_not_found;
    }

    pub fn getFileSize(filesystem: *Filesystem, file_path: []const u8) !u32 {
        const file = try filesystem.getModule(file_path);
        return @as(u32, @intCast(file.size));
    }

    pub fn getSectorSize(filesystem: *Filesystem) u16 {
        _ = filesystem;
        return lib.default_sector_size;
    }
};

const MemoryMap = struct {
    entries: []const limine.MemoryMap.Entry,
    index: usize = 0,

    pub fn getEntryCount(memory_map: *const MemoryMap) u32 {
        return @as(u32, @intCast(memory_map.entries.len));
    }

    pub fn next(memory_map: *MemoryMap) !?bootloader.MemoryMapEntry {
        if (memory_map.index < memory_map.entries.len) {
            const entry = memory_map.entries[memory_map.index];
            memory_map.index += 1;

            return .{
                .region = entry.region,
                .type = switch (entry.type) {
                    .usable => .usable,
                    .framebuffer, .kernel_and_modules, .bootloader_reclaimable, .reserved, .acpi_reclaimable, .acpi_nvs => .reserved,
                    .bad_memory => @panic("Bad memory"),
                },
            };
        }

        return null;
    }
};

const Initialization = struct {
    framebuffer: bootloader.Framebuffer,
    memory_map: MemoryMap,
    filesystem: Filesystem,
    architecture: switch (lib.cpu.arch) {
        .x86_64 => struct {
            rsdp: *ACPI.RSDP.Descriptor1,
        },
        else => @compileError("Architecture not supported"),
    },

    early_initialized: bool = false,
    framebuffer_initialized: bool = false,
    memory_map_initialized: bool = false,
    filesystem_initialized: bool = false,

    pub fn ensureLoaderIsMapped(init: *Initialization, minimal_paging: privileged.arch.paging.Specific, page_allocator: PageAllocator, bootloader_information: *bootloader.Information) !void {
        const Section = enum {
            text,
            rodata,
            data,
        };
        const physical_offset = request.kernel_address.response.?.physical_address;
        const virtual_offset = request.kernel_address.response.?.virtual_address;

        inline for (comptime lib.enumValues(Section)) |section| {
            const section_name = @tagName(section);
            const section_start = @intFromPtr(@extern(*const u8, .{ .name = section_name ++ "_section_start" }));
            const section_end = @intFromPtr(@extern(*const u8, .{ .name = section_name ++ "_section_end" }));

            const offset = section_start - virtual_offset;
            const physical_address = PhysicalAddress.new(physical_offset + offset);
            const virtual_address = VirtualAddress.new(section_start);
            const size = section_end - section_start;

            log.debug("Trying to map {s}: 0x{x} -> 0x{x} for 0x{x} bytes...", .{ section_name, virtual_address.value(), physical_address.value(), size });

            if (section == .text) {
                const address = @intFromPtr(&ensureLoaderIsMapped);
                assert(address >= section_start and address <= section_end);
            }

            try minimal_paging.map(physical_address, virtual_address, size, switch (section) {
                .text => .{ .write = false, .execute = true },
                .rodata => .{ .write = false, .execute = false },
                .data => .{ .write = true, .execute = false },
            }, page_allocator);
            log.debug("Mapped {s}...", .{section_name});
        }

        _ = init;
        _ = bootloader_information;
    }

    pub fn ensureStackIsMapped(init: *Initialization, minimal_paging: paging.Specific, page_allocator: PageAllocator) !void {
        _ = init;
        const rsp = switch (lib.cpu.arch) {
            .x86_64 => asm volatile (
                \\mov %rsp, %[result]
                : [result] "=r" (-> u64),
            ),
            .aarch64 => @panic("TODO ensureStackIsMapped"),
            else => @compileError("Architecture not supported"),
        };

        const memory_map = request.memory_map.response.?;
        const memory_map_entries = memory_map.entries.*[0..memory_map.entry_count];
        for (memory_map_entries) |entry| {
            if (entry.type == .bootloader_reclaimable) {
                if (entry.region.address.toHigherHalfVirtualAddress().value() < rsp and entry.region.address.offset(entry.region.size).toHigherHalfVirtualAddress().value() > rsp) {
                    try minimal_paging.map(entry.region.address, entry.region.address.toHigherHalfVirtualAddress(), entry.region.size, .{ .write = true, .execute = false }, page_allocator);
                    break;
                }
            }
        } else @panic("Can't find memory map region for RSP");
    }

    pub fn getCPUCount(init: *Initialization) !u32 {
        return switch (lib.cpu.arch) {
            .x86_64 => blk: {
                const rsdp = init.architecture.rsdp;
                const madt_header = try rsdp.findTable(.APIC);
                const madt = @as(*align(1) const ACPI.MADT, @ptrCast(madt_header));
                const cpu_count = madt.getCPUCount();
                break :blk cpu_count;
            },
            else => @compileError("Architecture not supported"),
        };
    }

    pub fn getRSDPAddress(init: *Initialization) usize {
        return @intFromPtr(init.architecture.rsdp);
    }

    pub fn deinitializeMemoryMap(init: *Initialization) !void {
        init.memory_map.index = 0;
    }

    fn initialize(init: *Initialization) !void {
        init.* = .{
            .framebuffer = blk: {
                if (request.framebuffer.response) |response| {
                    const framebuffers = response.framebuffers.*;
                    if (response.framebuffer_count > 0) {
                        const framebuffer = framebuffers[0];
                        break :blk .{
                            .address = framebuffer.address,
                            .pitch = @as(u32, @intCast(framebuffer.pitch)),
                            .width = @as(u32, @intCast(framebuffer.width)),
                            .height = @as(u32, @intCast(framebuffer.height)),
                            .bpp = framebuffer.bpp,
                            .red_mask = .{
                                .shift = framebuffer.red_mask_shift,
                                .size = framebuffer.red_mask_size,
                            },
                            .green_mask = .{
                                .shift = framebuffer.green_mask_shift,
                                .size = framebuffer.green_mask_size,
                            },
                            .blue_mask = .{
                                .shift = framebuffer.blue_mask_shift,
                                .size = framebuffer.blue_mask_size,
                            },
                            .memory_model = framebuffer.memory_model,
                        };
                    }
                }

                return Error.framebuffer_not_found;
            },
            .memory_map = blk: {
                if (request.memory_map.response) |response| {
                    if (response.entry_count > 0) {
                        const entries = response.entries.*[0..response.entry_count];
                        break :blk .{
                            .entries = entries,
                        };
                    }
                }

                return Error.memory_map_not_found;
            },
            .filesystem = blk: {
                if (request.modules.response) |response| {
                    if (response.module_count > 0) {
                        const modules = response.modules.*[0..response.module_count];
                        break :blk .{
                            .modules = modules,
                        };
                    }
                }
                return Error.filesystem_not_found;
            },
            .architecture = switch (lib.cpu.arch) {
                .x86_64 => .{
                    .rsdp = blk: {
                        if (request.rsdp.response) |response| {
                            break :blk @as(?*ACPI.RSDP.Descriptor1, @ptrFromInt(response.address)) orelse return Error.rsdp_not_found;
                        }

                        return Error.rsdp_not_found;
                    },
                },
                else => @compileError("Architecture not supported"),
            },
        };

        init.early_initialized = true;
        init.framebuffer_initialized = true;
        init.filesystem_initialized = true;
        init.memory_map_initialized = true;
    }
};

const Error = error{
    not_implemented,
    file_not_found,
    framebuffer_not_found,
    memory_map_not_found,
    filesystem_not_found,
    rsdp_not_found,
    protocol_not_found,
};

var initialization: Initialization = undefined;

export fn _start() callconv(.C) noreturn {
    main() catch |err| @panic(@errorName(err));
}

pub fn main() !noreturn {
    log.debug("Hello Limine!", .{});
    const limine_protocol: bootloader.Protocol = if (request.efi_system_table.response != null) .uefi else if (request.smbios.response != null) .bios else return Error.protocol_not_found;

    try initialization.initialize();

    switch (limine_protocol) {
        inline else => |protocol| try bootloader.Information.initialize(&initialization, .limine, protocol),
    }
}

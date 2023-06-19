const lib = @import("lib");
const assert = lib.assert;
const log = lib.log.scoped(.RUNNER);
const host = @import("host");
const Configuration = lib.Configuration;

const Error = error{
    wrong_argument_count,
    disk_image_path_not_found,
    cpu_driver_not_found,
    loader_path_not_found,
    qemu_options_not_found,
    configuration_not_found,
    configuration_wrong_argument,
    ci_not_found,
    debug_user_not_found,
    debug_loader_not_found,
    init_not_found,
    image_configuration_path_not_found,
    qemu_error,
    not_implemented,
    architecture_not_supported,
    execution_environment_not_supported,
};

pub fn main() anyerror!void {
    const max_file_length = lib.maxInt(usize);
    var arena_allocator = host.ArenaAllocator.init(host.page_allocator);
    defer arena_allocator.deinit();
    var wrapped_allocator = lib.Allocator.wrap(arena_allocator.allocator());

    const arguments_result: lib.ArgumentParser.Runner.Result = blk: {
        const arguments = (try host.allocateArguments(wrapped_allocator.zigUnwrap()))[1..];

        var argument_parser = lib.ArgumentParser.Runner{};
        var argument_disk_image_path: ?[]const u8 = null;
        var argument_cpu_driver_path: ?[]const u8 = null;
        var argument_loader_path: ?[]const u8 = null;
        var argument_qemu_options: ?lib.QEMUOptions = null;
        var argument_configuration: ?Configuration = null;
        var argument_image_configuration_path: ?[]const u8 = null;
        var argument_ci: ?bool = null;
        var argument_debug_user: ?bool = null;
        var argument_debug_loader: ?bool = null;
        var argument_init_path: ?[]const u8 = null;
        var argument_index: usize = 0;

        while (argument_parser.next()) |argument_type| switch (argument_type) {
            .disk_image_path => {
                argument_disk_image_path = arguments[argument_index];
                argument_index += 1;
            },
            .cpu_driver => {
                argument_cpu_driver_path = arguments[argument_index];
                argument_index += 1;
            },
            .loader_path => {
                argument_loader_path = arguments[argument_index];
                argument_index += 1;
            },
            .qemu_options => {
                const boolean_argument_strings = [2][]const u8{ arguments[argument_index], arguments[argument_index + 1] };
                argument_index += 2;

                argument_qemu_options = undefined;
                inline for (lib.fields(lib.QEMUOptions), 0..) |field, field_index| {
                    @field(argument_qemu_options.?, field.name) = if (lib.equal(u8, boolean_argument_strings[field_index], "true")) true else if (lib.equal(u8, boolean_argument_strings[field_index], "false")) false else return Error.qemu_options_not_found;
                }
            },
            .configuration => {
                argument_configuration = undefined;
                const configuration = &argument_configuration.?;
                inline for (lib.fields(Configuration)) |field| {
                    @field(configuration, field.name) = lib.stringToEnum(field.type, arguments[argument_index]) orelse return Error.configuration_wrong_argument;
                    argument_index += 1;
                }
            },
            .image_configuration_path => {
                argument_image_configuration_path = arguments[argument_index];
                argument_index += 1;
            },
            .ci => {
                argument_ci = if (lib.equal(u8, arguments[argument_index], "true")) true else if (lib.equal(u8, arguments[argument_index], "false")) false else return Error.ci_not_found;
                argument_index += 1;
            },
            .debug_user => {
                argument_debug_user = if (lib.equal(u8, arguments[argument_index], "true")) true else if (lib.equal(u8, arguments[argument_index], "false")) false else return Error.debug_user_not_found;
                argument_index += 1;
            },
            .debug_loader => {
                argument_debug_loader = if (lib.equal(u8, arguments[argument_index], "true")) true else if (lib.equal(u8, arguments[argument_index], "false")) false else return Error.debug_loader_not_found;
                argument_index += 1;
            },
            .init => {
                argument_init_path = arguments[argument_index];
                argument_index += 1;
            },
        };

        if (argument_index != arguments.len) return Error.wrong_argument_count;

        break :blk .{
            .disk_image_path = argument_disk_image_path orelse return Error.disk_image_path_not_found,
            .cpu_driver = argument_cpu_driver_path orelse return Error.cpu_driver_not_found,
            .loader_path = argument_loader_path orelse return Error.loader_path_not_found,
            .qemu_options = argument_qemu_options orelse return Error.qemu_options_not_found,
            .configuration = argument_configuration orelse return Error.configuration_not_found,
            .image_configuration_path = argument_image_configuration_path orelse return Error.image_configuration_path_not_found,
            .ci = argument_ci orelse return Error.ci_not_found,
            .debug_user = argument_debug_user orelse return Error.debug_user_not_found,
            .debug_loader = argument_debug_loader orelse return Error.debug_loader_not_found,
            .init = argument_init_path orelse return Error.init_not_found,
        };
    };

    switch (arguments_result.configuration.execution_environment) {
        .qemu => {
            const qemu_options = arguments_result.qemu_options;

            const config_file = try host.cwd().readFileAlloc(wrapped_allocator.zigUnwrap(), "config/qemu.json", max_file_length);
            const parsed_arguments = try lib.json.parseFromSlice(Arguments, wrapped_allocator.zigUnwrap(), config_file, .{});
            const arguments = parsed_arguments.value;

            var argument_list = host.ArrayList([]const u8).init(wrapped_allocator.zigUnwrap());

            try argument_list.append(try lib.concat(wrapped_allocator.zigUnwrap(), u8, &.{ "qemu-system-", @tagName(arguments_result.configuration.architecture) }));

            if (qemu_options.is_test and !qemu_options.is_debug) {
                try argument_list.appendSlice(&.{ "-device", try lib.allocPrint(wrapped_allocator.zigUnwrap(), "isa-debug-exit,iobase=0x{x:0>2},iosize=0x{x:0>2}", .{ lib.QEMU.isa_debug_exit.io_base, lib.QEMU.isa_debug_exit.io_size }) });
            }

            switch (arguments_result.configuration.boot_protocol) {
                .uefi => try argument_list.appendSlice(&.{ "-bios", "tools/OVMF_CODE-pure-efi.fd" }),
                else => {},
            }

            const image_config = try lib.ImageConfig.get(wrapped_allocator.zigUnwrap(), arguments_result.image_configuration_path);
            _ = image_config;
            const disk_image_path = arguments_result.disk_image_path;
            try argument_list.appendSlice(&.{ "-drive", try lib.allocPrint(wrapped_allocator.zigUnwrap(), "file={s},index=0,media=disk,format=raw", .{disk_image_path}) });

            try argument_list.append("-no-reboot");

            if (!qemu_options.is_test) {
                try argument_list.append("-no-shutdown");
            }

            if (arguments_result.ci) {
                try argument_list.appendSlice(&.{ "-display", "none" });
            }

            //if (arguments.vga) |vga| {
            //try argument_list.append("-vga");
            //try argument_list.append(@tagName(vga));
            //}

            if (arguments.smp) |smp| {
                try argument_list.append("-smp");
                const smp_string = try lib.allocPrint(wrapped_allocator.zigUnwrap(), "{}", .{smp});
                try argument_list.append(smp_string);
            }

            if (arguments.debugcon) |debugcon| {
                try argument_list.append("-debugcon");
                try argument_list.append(@tagName(debugcon));
            }

            if (arguments.memory) |memory| {
                try argument_list.append("-m");
                if (arguments_result.ci) {
                    try argument_list.append("1G");
                } else {
                    const memory_argument = try lib.allocPrint(wrapped_allocator.zigUnwrap(), "{}{c}", .{ memory.amount, @as(u8, switch (memory.unit) {
                        .kilobyte => 'K',
                        .megabyte => 'M',
                        .gigabyte => 'G',
                        else => @panic("Unit too big"),
                    }) });
                    try argument_list.append(memory_argument);
                }
            }

            if (lib.canVirtualizeWithQEMU(arguments_result.configuration.architecture, arguments_result.ci) and (arguments_result.configuration.execution_type == .accelerated or (arguments.virtualize orelse false))) {
                try argument_list.appendSlice(&.{
                    "-accel",
                    switch (lib.os) {
                        .windows => "whpx",
                        .linux => "kvm",
                        .macos => "hvf",
                        else => @compileError("OS not supported"),
                    },
                    "-cpu",
                    "host",
                });
            } else {
                switch (arguments_result.configuration.architecture) {
                    .x86_64 => try argument_list.appendSlice(&.{ "-cpu", "max" }),
                    else => return Error.architecture_not_supported,
                }

                if (arguments.trace) |tracees| {
                    for (tracees) |tracee| {
                        const tracee_slice = try lib.allocPrint(wrapped_allocator.zigUnwrap(), "-{s}*", .{tracee});
                        try argument_list.append("-trace");
                        try argument_list.append(tracee_slice);
                    }
                }

                if (!arguments_result.ci) {
                    if (arguments.log) |log_configuration| {
                        var log_what = host.ArrayList(u8).init(wrapped_allocator.zigUnwrap());

                        if (log_configuration.guest_errors) try log_what.appendSlice("guest_errors,");
                        if (log_configuration.interrupts) try log_what.appendSlice("int,");
                        if (!arguments_result.ci and log_configuration.assembly) try log_what.appendSlice("in_asm,");

                        if (log_what.items.len > 0) {
                            // Delete the last comma
                            _ = log_what.pop();

                            try argument_list.append("-d");
                            try argument_list.append(log_what.items);

                            if (log_configuration.interrupts) {
                                try argument_list.appendSlice(&.{ "-machine", "smm=off" });
                            }
                        }

                        if (log_configuration.file) |log_file| {
                            try argument_list.append("-D");
                            try argument_list.append(log_file);
                        }
                    }
                }
            }

            if (qemu_options.is_debug) {
                try argument_list.append("-s");
                if (!(arguments_result.configuration.execution_type == .accelerated or (arguments.virtualize orelse false))) {
                    try argument_list.append("-S");
                }

                // GF2, when not found in the PATH, can give problems
                const use_gf = switch (lib.os) {
                    .macos => false,
                    .linux => false,
                    else => false,
                };

                var command_line_gdb = host.ArrayList([]const u8).init(wrapped_allocator.zigUnwrap());
                if (use_gf) {
                    try command_line_gdb.append("gf2");
                } else {
                    try command_line_gdb.append("kitty");
                    try command_line_gdb.append(switch (lib.os) {
                        .linux => "gdb",
                        .macos => "x86_64-elf-gdb",
                        else => "gdb",
                    });
                }

                try command_line_gdb.appendSlice(&.{ "-ex", switch (arguments_result.configuration.architecture) {
                    .x86_64 => "set disassembly-flavor intel\n",
                    else => return Error.architecture_not_supported,
                } });

                try command_line_gdb.appendSlice(&.{ "-ex", "target remote localhost:1234" });
                if (arguments_result.debug_user) {
                    assert(!arguments_result.debug_loader);
                    try command_line_gdb.appendSlice(&.{ "-ex", try lib.allocPrint(wrapped_allocator.zigUnwrap(), "symbol-file {s}", .{arguments_result.init}) });
                } else if (arguments_result.debug_loader) {
                    assert(!arguments_result.debug_user);
                    try command_line_gdb.appendSlice(&.{ "-ex", try lib.allocPrint(wrapped_allocator.zigUnwrap(), "symbol-file {s}", .{arguments_result.loader_path}) });
                } else {
                    try command_line_gdb.appendSlice(&.{ "-ex", try lib.allocPrint(wrapped_allocator.zigUnwrap(), "symbol-file {s}", .{arguments_result.cpu_driver}) });
                }

                const gdb_script_file = try host.cwd().openFile("config/gdb_script", .{});
                var gdb_script_reader = gdb_script_file.reader();
                while (try gdb_script_reader.readUntilDelimiterOrEofAlloc(wrapped_allocator.zigUnwrap(), '\n', max_file_length)) |gdb_script_line| {
                    try command_line_gdb.appendSlice(&.{ "-ex", gdb_script_line });
                }

                const debugger_process_arguments = switch (lib.os) {
                    .linux, .macos => command_line_gdb.items,
                    else => return Error.not_implemented,
                };

                var debugger_process = host.ChildProcess.init(debugger_process_arguments, wrapped_allocator.zigUnwrap());
                try debugger_process.spawn();
            }

            var process = host.ChildProcess.init(argument_list.items, wrapped_allocator.zigUnwrap());
            const result = try process.spawnAndWait();

            if (result == .Exited) {
                const exit_code = result.Exited;
                if (exit_code & 1 != 0) {
                    const mask = lib.maxInt(@TypeOf(exit_code)) - 1;
                    const masked_exit_code = exit_code & mask;

                    if (masked_exit_code != 0) {
                        const qemu_exit_code = @as(lib.QEMU.ExitCode, @enumFromInt(masked_exit_code >> 1));

                        switch (qemu_exit_code) {
                            .success => return log.info("Success!", .{}),
                            .failure => log.err("QEMU exited with failure code 0x{x}", .{exit_code}),
                            _ => log.err("Totally unexpected value", .{}),
                        }
                    } else log.err("QEMU exited with unexpected code: {}. Masked: {}", .{ exit_code, masked_exit_code });
                } else log.err("QEMU exited with unexpected code: {}", .{exit_code});
            } else {
                log.err("QEMU was {s}", .{@tagName(result)});
            }

            return Error.qemu_error;
        },
    }
}

const Arguments = struct {
    const VGA = enum {
        std,
        cirrus,
        vmware,
        qxl,
        xenfb,
        tcx,
        cg3,
        virtio,
        none,
    };
    memory: ?struct {
        amount: u64,
        unit: lib.SizeUnit,
    },
    virtualize: ?bool,
    vga: ?VGA,
    smp: ?usize,
    debugcon: ?enum {
        stdio,
    },
    log: ?struct {
        file: ?[]const u8,
        guest_errors: bool,
        assembly: bool,
        interrupts: bool,
    },
    trace: ?[]const []const u8,
};

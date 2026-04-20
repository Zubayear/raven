const std = @import("std");

pub const Config = struct {
    listen_address: []const u8 = "127.0.0.1",
    listen_port: u16 = 5882,
    imap_port: u16 = 1143,
    hostname: []const u8 = "localhost",
    data_dir: []const u8 = "data",
    tls_cert_file: []const u8 = "",
    tls_key_file: []const u8 = "",
    config_path: ?[]const u8 = null,

    pub fn load(process: std.process.Init) !Config {
        const arena = process.arena.allocator();
        const args = try parseArgs(process, arena);

        const config_path = args.config_path orelse try getEnvValue(process, "RAVEN_CONFIG");
        var config = if (config_path) |path| try loadFile(process.io, arena, path) else Config{};
        config.config_path = config_path;

        try applyEnv(&config, process, arena);
        applyArgs(&config, args);
        try config.validate();
        return config;
    }

    pub fn validate(self: Config) !void {
        if (self.listen_address.len == 0) return error.InvalidConfig;
        if (self.hostname.len == 0) return error.InvalidConfig;
        if (self.data_dir.len == 0) return error.InvalidConfig;
        if (self.listen_port == 0 or self.imap_port == 0) return error.InvalidConfig;
    }
};

const ArgsOptions = struct {
    config_path: ?[]const u8 = null,
    listen_address: ?[]const u8 = null,
    listen_port: ?u16 = null,
    imap_port: ?u16 = null,
    hostname: ?[]const u8 = null,
    data_dir: ?[]const u8 = null,
    tls_cert_file: ?[]const u8 = null,
    tls_key_file: ?[]const u8 = null,
};

fn parseArgs(process: std.process.Init, arena: std.mem.Allocator) !ArgsOptions {
    var it = try std.process.Args.Iterator.initAllocator(process.minimal.args, process.gpa);
    defer it.deinit();

    _ = it.next();
    var args = ArgsOptions{};
    while (it.next()) |arg| {
        if (std.mem.eql(u8, arg, "--config")) {
            args.config_path = try arena.dupe(u8, it.next() orelse return error.MissingConfigValue);
            continue;
        }
        if (std.mem.eql(u8, arg, "--listen-address")) {
            args.listen_address = try arena.dupe(u8, it.next() orelse return error.MissingConfigValue);
            continue;
        }
        if (std.mem.eql(u8, arg, "--listen-port")) {
            args.listen_port = try parsePort(it.next() orelse return error.MissingConfigValue);
            continue;
        }
        if (std.mem.eql(u8, arg, "--imap-port")) {
            args.imap_port = try parsePort(it.next() orelse return error.MissingConfigValue);
            continue;
        }
        if (std.mem.eql(u8, arg, "--hostname")) {
            args.hostname = try arena.dupe(u8, it.next() orelse return error.MissingConfigValue);
            continue;
        }
        if (std.mem.eql(u8, arg, "--data-dir")) {
            args.data_dir = try arena.dupe(u8, it.next() orelse return error.MissingConfigValue);
            continue;
        }
        if (std.mem.eql(u8, arg, "--tls-cert")) {
            args.tls_cert_file = try arena.dupe(u8, it.next() orelse return error.MissingConfigValue);
            continue;
        }
        if (std.mem.eql(u8, arg, "--tls-key")) {
            args.tls_key_file = try arena.dupe(u8, it.next() orelse return error.MissingConfigValue);
            continue;
        }
    }
    return args;
}

fn applyArgs(config: *Config, args: ArgsOptions) void {
    if (args.listen_address) |value| config.listen_address = value;
    if (args.listen_port) |value| config.listen_port = value;
    if (args.imap_port) |value| config.imap_port = value;
    if (args.hostname) |value| config.hostname = value;
    if (args.data_dir) |value| config.data_dir = value;
    if (args.tls_cert_file) |value| config.tls_cert_file = value;
    if (args.tls_key_file) |value| config.tls_key_file = value;
}

fn applyEnv(config: *Config, process: std.process.Init, arena: std.mem.Allocator) !void {
    if (try getEnvValue(process, "RAVEN_LISTEN_ADDRESS")) |value| config.listen_address = try arena.dupe(u8, value);
    if (try getEnvValue(process, "RAVEN_LISTEN_PORT")) |value| config.listen_port = try parsePort(value);
    if (try getEnvValue(process, "RAVEN_IMAP_PORT")) |value| config.imap_port = try parsePort(value);
    if (try getEnvValue(process, "RAVEN_HOSTNAME")) |value| config.hostname = try arena.dupe(u8, value);
    if (try getEnvValue(process, "RAVEN_DATA_DIR")) |value| config.data_dir = try arena.dupe(u8, value);
    if (try getEnvValue(process, "RAVEN_TLS_CERT")) |value| config.tls_cert_file = try arena.dupe(u8, value);
    if (try getEnvValue(process, "RAVEN_TLS_KEY")) |value| config.tls_key_file = try arena.dupe(u8, value);
}

fn getEnvValue(process: std.process.Init, key: []const u8) !?[]const u8 {
    return process.minimal.environ.getAlloc(process.gpa, key) catch |err| switch (err) {
        error.EnvironmentVariableMissing => null,
        else => return err,
    };
}

pub fn loadFile(io: std.Io, allocator: std.mem.Allocator, path: []const u8) !Config {
    const raw = try std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(16 * 1024));
    defer allocator.free(raw);
    return parseText(raw, allocator);
}

pub fn parseText(raw: []const u8, allocator: std.mem.Allocator) !Config {
    var config = Config{};
    var lines = std.mem.tokenizeScalar(u8, raw, '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (trimmed.len == 0 or trimmed[0] == '#') continue;

        const eq = std.mem.indexOfScalar(u8, trimmed, '=') orelse return error.InvalidConfig;
        const key = std.mem.trim(u8, trimmed[0..eq], " \t");
        const value = std.mem.trim(u8, trimmed[eq + 1 ..], " \t");
        try applyKeyValue(&config, allocator, key, value);
    }
    return config;
}

fn applyKeyValue(config: *Config, allocator: std.mem.Allocator, key: []const u8, value: []const u8) !void {
    if (std.mem.eql(u8, key, "listen_address")) {
        config.listen_address = try allocator.dupe(u8, value);
        return;
    }
    if (std.mem.eql(u8, key, "listen_port")) {
        config.listen_port = try parsePort(value);
        return;
    }
    if (std.mem.eql(u8, key, "imap_port")) {
        config.imap_port = try parsePort(value);
        return;
    }
    if (std.mem.eql(u8, key, "hostname")) {
        config.hostname = try allocator.dupe(u8, value);
        return;
    }
    if (std.mem.eql(u8, key, "data_dir")) {
        config.data_dir = try allocator.dupe(u8, value);
        return;
    }
    if (std.mem.eql(u8, key, "tls_cert_file")) {
        config.tls_cert_file = try allocator.dupe(u8, value);
        return;
    }
    if (std.mem.eql(u8, key, "tls_key_file")) {
        config.tls_key_file = try allocator.dupe(u8, value);
        return;
    }
}

fn parsePort(value: []const u8) !u16 {
    const port = try std.fmt.parseInt(u16, value, 10);
    if (port == 0) return error.InvalidPort;
    return port;
}

test "parseText reads config values" {
    const allocator = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const raw =
        \\listen_address = 0.0.0.0
        \\listen_port = 2525
        \\imap_port = 1144
        \\hostname = mail.example.com
        \\data_dir = /srv/raven
    ;

    const config = try parseText(raw, a);
    try std.testing.expectEqualStrings("0.0.0.0", config.listen_address);
    try std.testing.expectEqual(@as(u16, 2525), config.listen_port);
    try std.testing.expectEqual(@as(u16, 1144), config.imap_port);
    try std.testing.expectEqualStrings("mail.example.com", config.hostname);
    try std.testing.expectEqualStrings("/srv/raven", config.data_dir);
}

test "parseText ignores comments and blanks" {
    const allocator = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const config = try parseText(
        \\# comment
        \\
        \\listen_port = 2526
        \\
    , a);
    try std.testing.expectEqual(@as(u16, 2526), config.listen_port);
}

test "validate rejects empty values" {
    try std.testing.expectError(error.InvalidConfig, (Config{ .listen_address = "", .hostname = "mail", .data_dir = "data" }).validate());
    try std.testing.expectError(error.InvalidConfig, (Config{ .listen_address = "127.0.0.1", .hostname = "", .data_dir = "data" }).validate());
    try std.testing.expectError(error.InvalidConfig, (Config{ .listen_address = "127.0.0.1", .hostname = "mail", .data_dir = "" }).validate());
}

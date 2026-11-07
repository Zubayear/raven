const std = @import("std");

pub const Config = struct {
    listen_address: []const u8 = "127.0.0.1",
    listen_port: u16 = 5882,
    imap_port: u16 = 1143,
    /// Implicit-TLS SMTP (usually 465); 0 disables it.
    smtps_port: u16 = 0,
    /// Implicit-TLS IMAP (usually 993); 0 disables it.
    imaps_port: u16 = 0,
    /// Mail submission (usually 587, RFC 6409): AUTH required; 0 disables it.
    submission_port: u16 = 0,
    /// Send all outbound mail through this host instead of the recipients'
    /// MX hosts (a smarthost); empty means direct delivery.
    relay_host: []const u8 = "",
    relay_port: u16 = 25,
    hostname: []const u8 = "localhost",
    data_dir: []const u8 = "data",
    tls_cert_file: []const u8 = "",
    tls_key_file: []const u8 = "",
    /// Per listener; further clients are turned away with 421 / BYE.
    max_connections: u32 = 100,
    /// Per listener and client address (IPv6: per /64).
    max_connections_per_ip: u32 = 20,
    /// Largest accepted message in bytes, advertised with SMTP SIZE.
    max_message_size: u64 = 25 * 1024 * 1024,
    /// Accept AUTH without TLS. Only for local testing.
    allow_plaintext_auth: bool = false,
    /// Least severe level logged: err, warn, info or debug.
    log_level: std.log.Level = .info,
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
        if (self.max_connections == 0 or self.max_connections_per_ip == 0 or self.max_message_size == 0) return error.InvalidConfig;
        if ((self.smtps_port != 0 or self.imaps_port != 0) and self.tls_cert_file.len == 0) return error.InvalidConfig;
    }
};

const ArgsOptions = struct {
    config_path: ?[]const u8 = null,
    listen_address: ?[]const u8 = null,
    listen_port: ?u16 = null,
    imap_port: ?u16 = null,
    smtps_port: ?u16 = null,
    imaps_port: ?u16 = null,
    submission_port: ?u16 = null,
    relay_host: ?[]const u8 = null,
    relay_port: ?u16 = null,
    hostname: ?[]const u8 = null,
    data_dir: ?[]const u8 = null,
    tls_cert_file: ?[]const u8 = null,
    tls_key_file: ?[]const u8 = null,
    max_connections: ?u32 = null,
    max_connections_per_ip: ?u32 = null,
    max_message_size: ?u64 = null,
    allow_plaintext_auth: ?bool = null,
    log_level: ?std.log.Level = null,
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
        if (std.mem.eql(u8, arg, "--smtps-port")) {
            args.smtps_port = try parsePort(it.next() orelse return error.MissingConfigValue);
            continue;
        }
        if (std.mem.eql(u8, arg, "--imaps-port")) {
            args.imaps_port = try parsePort(it.next() orelse return error.MissingConfigValue);
            continue;
        }
        if (std.mem.eql(u8, arg, "--submission-port")) {
            args.submission_port = try parsePort(it.next() orelse return error.MissingConfigValue);
            continue;
        }
        if (std.mem.eql(u8, arg, "--relay-host")) {
            args.relay_host = try arena.dupe(u8, it.next() orelse return error.MissingConfigValue);
            continue;
        }
        if (std.mem.eql(u8, arg, "--relay-port")) {
            args.relay_port = try parsePort(it.next() orelse return error.MissingConfigValue);
            continue;
        }
        if (std.mem.eql(u8, arg, "--log-level")) {
            args.log_level = try parseLogLevel(it.next() orelse return error.MissingConfigValue);
            continue;
        }
        if (std.mem.eql(u8, arg, "--allow-plaintext-auth")) {
            args.allow_plaintext_auth = true;
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
        if (std.mem.eql(u8, arg, "--max-connections")) {
            args.max_connections = try std.fmt.parseInt(u32, it.next() orelse return error.MissingConfigValue, 10);
            continue;
        }
        if (std.mem.eql(u8, arg, "--max-connections-per-ip")) {
            args.max_connections_per_ip = try std.fmt.parseInt(u32, it.next() orelse return error.MissingConfigValue, 10);
            continue;
        }
        if (std.mem.eql(u8, arg, "--max-message-size")) {
            args.max_message_size = try std.fmt.parseInt(u64, it.next() orelse return error.MissingConfigValue, 10);
            continue;
        }
    }
    return args;
}

fn applyArgs(config: *Config, args: ArgsOptions) void {
    if (args.listen_address) |value| config.listen_address = value;
    if (args.listen_port) |value| config.listen_port = value;
    if (args.imap_port) |value| config.imap_port = value;
    if (args.smtps_port) |value| config.smtps_port = value;
    if (args.imaps_port) |value| config.imaps_port = value;
    if (args.submission_port) |value| config.submission_port = value;
    if (args.relay_host) |value| config.relay_host = value;
    if (args.relay_port) |value| config.relay_port = value;
    if (args.allow_plaintext_auth) |value| config.allow_plaintext_auth = value;
    if (args.log_level) |value| config.log_level = value;
    if (args.hostname) |value| config.hostname = value;
    if (args.data_dir) |value| config.data_dir = value;
    if (args.tls_cert_file) |value| config.tls_cert_file = value;
    if (args.tls_key_file) |value| config.tls_key_file = value;
    if (args.max_connections) |value| config.max_connections = value;
    if (args.max_connections_per_ip) |value| config.max_connections_per_ip = value;
    if (args.max_message_size) |value| config.max_message_size = value;
}

fn applyEnv(config: *Config, process: std.process.Init, arena: std.mem.Allocator) !void {
    if (try getEnvValue(process, "RAVEN_LISTEN_ADDRESS")) |value| config.listen_address = try arena.dupe(u8, value);
    if (try getEnvValue(process, "RAVEN_LISTEN_PORT")) |value| config.listen_port = try parsePort(value);
    if (try getEnvValue(process, "RAVEN_IMAP_PORT")) |value| config.imap_port = try parsePort(value);
    if (try getEnvValue(process, "RAVEN_SMTPS_PORT")) |value| config.smtps_port = try parsePort(value);
    if (try getEnvValue(process, "RAVEN_IMAPS_PORT")) |value| config.imaps_port = try parsePort(value);
    if (try getEnvValue(process, "RAVEN_SUBMISSION_PORT")) |value| config.submission_port = try parsePort(value);
    if (try getEnvValue(process, "RAVEN_RELAY_HOST")) |value| config.relay_host = try arena.dupe(u8, value);
    if (try getEnvValue(process, "RAVEN_RELAY_PORT")) |value| config.relay_port = try parsePort(value);
    if (try getEnvValue(process, "RAVEN_ALLOW_PLAINTEXT_AUTH")) |value| config.allow_plaintext_auth = try parseBool(value);
    if (try getEnvValue(process, "RAVEN_LOG_LEVEL")) |value| config.log_level = try parseLogLevel(value);
    if (try getEnvValue(process, "RAVEN_HOSTNAME")) |value| config.hostname = try arena.dupe(u8, value);
    if (try getEnvValue(process, "RAVEN_DATA_DIR")) |value| config.data_dir = try arena.dupe(u8, value);
    if (try getEnvValue(process, "RAVEN_TLS_CERT")) |value| config.tls_cert_file = try arena.dupe(u8, value);
    if (try getEnvValue(process, "RAVEN_TLS_KEY")) |value| config.tls_key_file = try arena.dupe(u8, value);
    if (try getEnvValue(process, "RAVEN_MAX_CONNECTIONS")) |value| config.max_connections = try std.fmt.parseInt(u32, value, 10);
    if (try getEnvValue(process, "RAVEN_MAX_CONNECTIONS_PER_IP")) |value| config.max_connections_per_ip = try std.fmt.parseInt(u32, value, 10);
    if (try getEnvValue(process, "RAVEN_MAX_MESSAGE_SIZE")) |value| config.max_message_size = try std.fmt.parseInt(u64, value, 10);
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
    if (std.mem.eql(u8, key, "smtps_port")) {
        config.smtps_port = try parsePort(value);
        return;
    }
    if (std.mem.eql(u8, key, "imaps_port")) {
        config.imaps_port = try parsePort(value);
        return;
    }
    if (std.mem.eql(u8, key, "submission_port")) {
        config.submission_port = try parsePort(value);
        return;
    }
    if (std.mem.eql(u8, key, "relay_host")) {
        config.relay_host = try allocator.dupe(u8, value);
        return;
    }
    if (std.mem.eql(u8, key, "relay_port")) {
        config.relay_port = try parsePort(value);
        return;
    }
    if (std.mem.eql(u8, key, "allow_plaintext_auth")) {
        config.allow_plaintext_auth = try parseBool(value);
        return;
    }
    if (std.mem.eql(u8, key, "log_level")) {
        config.log_level = try parseLogLevel(value);
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
    if (std.mem.eql(u8, key, "max_connections")) {
        config.max_connections = try std.fmt.parseInt(u32, value, 10);
        return;
    }
    if (std.mem.eql(u8, key, "max_connections_per_ip")) {
        config.max_connections_per_ip = try std.fmt.parseInt(u32, value, 10);
        return;
    }
    if (std.mem.eql(u8, key, "max_message_size")) {
        config.max_message_size = try std.fmt.parseInt(u64, value, 10);
        return;
    }
}

fn parseBool(value: []const u8) !bool {
    for ([_][]const u8{ "1", "true", "yes", "on" }) |t| if (std.ascii.eqlIgnoreCase(value, t)) return true;
    for ([_][]const u8{ "0", "false", "no", "off" }) |f| if (std.ascii.eqlIgnoreCase(value, f)) return false;
    return error.InvalidConfig;
}

fn parseLogLevel(value: []const u8) !std.log.Level {
    return std.meta.stringToEnum(std.log.Level, value) orelse error.InvalidConfig;
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
        \\log_level = debug
    ;

    const config = try parseText(raw, a);
    try std.testing.expectEqualStrings("0.0.0.0", config.listen_address);
    try std.testing.expectEqual(@as(u16, 2525), config.listen_port);
    try std.testing.expectEqual(@as(u16, 1144), config.imap_port);
    try std.testing.expectEqualStrings("mail.example.com", config.hostname);
    try std.testing.expectEqualStrings("/srv/raven", config.data_dir);
    try std.testing.expectEqual(std.log.Level.debug, config.log_level);
    try std.testing.expectError(error.InvalidConfig, parseText("log_level = verbose", a));
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

const std = @import("std");

const Io = std.Io;
const account_index = @import("account_index.zig");
const AccountStore = account_index.AccountStore;
const Identity = account_index.Identity;
const address = @import("address.zig");
const Config = @import("config.zig").Config;
const AliasTable = @import("alias_index.zig").AliasTable;
const Storage = @import("storage.zig").Storage;
const TenantCatalog = @import("tenant_index.zig").TenantCatalog;
const TenantIndex = @import("tenant_index.zig");
const conn = @import("conn.zig");
const dkim = @import("dkim.zig");

pub const Server = struct {
    allocator: std.mem.Allocator,
    config: Config,
    storage: Storage,
    tenant_catalog: *const TenantCatalog,
    /// The submission port (587): every transaction needs AUTH.
    submission: bool = false,

    pub fn init(allocator: std.mem.Allocator, config: Config, tenant_catalog: *const TenantCatalog) Server {
        return .{
            .allocator = allocator,
            .config = config,
            .storage = Storage.init(config.data_dir),
            .tenant_catalog = tenant_catalog,
        };
    }

    /// Passwords only travel encrypted, unless the operator opted out.
    fn authAllowed(self: *const Server, client: *const conn.Client) bool {
        return client.secure or self.config.allow_plaintext_auth;
    }

    /// A DKIM-Signature for `message` from `identity`'s domain, or null if
    /// the domain has no key or signing fails: the mail then goes unsigned.
    fn dkimSignature(self: *const Server, io: Io, identity: Identity, message: []const u8, seconds: u64) ?[]u8 {
        const key_dir = self.storage.dkimPath(self.allocator, identity.tenant, identity.domain) catch return null;
        defer self.allocator.free(key_dir);
        const key = (dkim.loadKey(self.allocator, io, key_dir) catch |err| {
            std.debug.print("dkim: cannot load key for {s}: {}\n", .{ identity.domain, err });
            return null;
        }) orelse return null;
        defer key.deinit(self.allocator);
        return dkim.sign(self.allocator, key, identity.domain, message, seconds) catch |err| {
            std.debug.print("dkim: signing for {s} failed: {}\n", .{ identity.domain, err });
            return null;
        };
    }

    pub fn listen(self: *Server, io: Io, port: u16) !std.Io.net.Server {
        const ip = try std.Io.net.IpAddress.parse(self.config.listen_address, port);
        const listener = try ip.listen(io, .{ .reuse_address = true });
        std.debug.print("smtp listening on {any}\n", .{ip});
        return listener;
    }

    pub fn handleClient(self: *Server, fs_io: Io, client: *conn.Client) !void {
        const allocator = self.allocator;
        // Both change when STARTTLS upgrades the connection.
        var r = client.reader;
        var w = client.writer;
        const catalog = self.tenant_catalog;
        try w.print("220 {s} ESMTP raven ready\r\n", .{self.config.hostname});

        // Client's HELO/EHLO name, for Received headers; null until greeted.
        var helo: ?[]u8 = null;
        defer if (helo) |name| allocator.free(name);
        var extended = false; // EHLO rather than HELO
        var auth_identity: ?Identity = null;
        defer if (auth_identity) |value| value.deinit(allocator);
        var tx: Transaction = .{};
        defer tx.deinit(allocator);

        while (true) {
            const line = switch (try readLine(r) orelse return) {
                .too_long => {
                    try w.writeAll("500 5.5.2 line too long\r\n");
                    continue;
                },
                .line => |line| line,
            };
            const verb, const args = splitVerb(line);
            // AUTH lines may carry a long initial response (RFC 4954 §4).
            if (line.len + 2 > max_command_line and !std.ascii.eqlIgnoreCase(verb, "AUTH")) {
                try w.writeAll("500 5.5.2 line too long\r\n");
                continue;
            }

            if (std.ascii.eqlIgnoreCase(verb, "QUIT")) {
                try w.writeAll("221 2.0.0 bye\r\n");
                return;
            } else if (std.ascii.eqlIgnoreCase(verb, "NOOP")) {
                try w.writeAll("250 2.0.0 ok\r\n");
            } else if (std.ascii.eqlIgnoreCase(verb, "RSET")) {
                tx.reset(allocator);
                try w.writeAll("250 2.0.0 ok\r\n");
            } else if (std.ascii.eqlIgnoreCase(verb, "VRFY")) {
                // Never confirm whether an account exists.
                try w.writeAll("252 2.5.0 cannot verify, but will attempt delivery\r\n");
            } else if (std.ascii.eqlIgnoreCase(verb, "EHLO") or std.ascii.eqlIgnoreCase(verb, "HELO")) {
                if (args.len == 0) {
                    try w.writeAll("501 5.5.4 syntax: EHLO hostname\r\n");
                    continue;
                }
                tx.reset(allocator);
                const name = try allocator.dupe(u8, args);
                if (helo) |old| allocator.free(old);
                helo = name;
                extended = std.ascii.eqlIgnoreCase(verb, "EHLO");
                if (!extended) {
                    try w.print("250 {s}\r\n", .{self.config.hostname});
                } else {
                    try w.print("250-{s}\r\n250-PIPELINING\r\n250-SIZE {d}\r\n250-8BITMIME\r\n", .{ self.config.hostname, self.config.max_message_size });
                    if (client.canStartTls()) try w.writeAll("250-STARTTLS\r\n");
                    if (self.authAllowed(client)) try w.writeAll("250-AUTH PLAIN\r\n");
                    try w.writeAll("250 ENHANCEDSTATUSCODES\r\n");
                }
            } else if (std.ascii.eqlIgnoreCase(verb, "STARTTLS")) {
                if (args.len != 0) {
                    try w.writeAll("501 5.5.4 syntax: STARTTLS\r\n");
                    continue;
                }
                if (!client.canStartTls()) {
                    try w.writeAll(if (client.secure) "503 5.5.1 TLS already active\r\n" else "454 4.7.0 TLS not available\r\n");
                    continue;
                }
                try w.writeAll("220 2.0.0 ready to start TLS\r\n");
                // A failed handshake leaves the stream in an unknown state: hang up.
                try client.startTls();
                r = client.reader;
                w = client.writer;
                // RFC 3207 §4.2: forget everything learned before the upgrade.
                if (helo) |name| allocator.free(name);
                helo = null;
                tx.reset(allocator);
                if (auth_identity) |value| value.deinit(allocator);
                auth_identity = null;
            } else if (helo == null and isTransactionVerb(verb)) {
                try w.writeAll("503 5.5.1 send EHLO first\r\n");
            } else if (std.ascii.eqlIgnoreCase(verb, "AUTH")) {
                if (!self.authAllowed(client)) {
                    try w.writeAll("538 5.7.11 encryption required for authentication\r\n");
                    continue;
                }
                if (auth_identity != null) {
                    try w.writeAll("503 5.5.1 already authenticated\r\n");
                    continue;
                }
                if (tx.sender != null) {
                    try w.writeAll("503 5.5.1 AUTH not allowed during a transaction\r\n");
                    continue;
                }
                var parts = std.mem.tokenizeScalar(u8, args, ' ');
                const mechanism = parts.next() orelse "";
                if (!std.ascii.eqlIgnoreCase(mechanism, "PLAIN")) {
                    try w.writeAll("504 5.5.4 mechanism not supported\r\n");
                    continue;
                }
                const response = parts.next() orelse response: {
                    try w.writeAll("334 \r\n");
                    break :response switch (try readLine(r) orelse return) {
                        .too_long => "",
                        .line => |reply| reply,
                    };
                };
                if (std.mem.eql(u8, response, "*")) {
                    try w.writeAll("501 5.0.0 authentication canceled\r\n");
                    continue;
                }
                auth_identity = account_index.authenticatePlain(allocator, fs_io, self.storage, catalog, response) catch |err| switch (err) {
                    error.AuthFailed => {
                        try w.writeAll("535 5.7.8 authentication failed\r\n");
                        continue;
                    },
                    else => return err,
                };
                try w.writeAll("235 2.7.0 authentication successful\r\n");
            } else if (std.ascii.eqlIgnoreCase(verb, "MAIL")) {
                if (tx.sender != null) {
                    try w.writeAll("503 5.5.1 nested MAIL command\r\n");
                    continue;
                }
                const path, const params = splitPath(afterPrefix(args, "FROM:") orelse {
                    try w.writeAll("501 5.5.4 syntax: MAIL FROM:<address>\r\n");
                    continue;
                });
                const declared_size = parseMailParams(params) catch {
                    try w.writeAll("555 5.5.4 unsupported MAIL parameter\r\n");
                    continue;
                };
                if (declared_size orelse 0 > self.config.max_message_size) {
                    try w.writeAll("552 5.3.4 message size exceeds limit\r\n");
                    continue;
                }
                if (self.submission and auth_identity == null) {
                    try w.writeAll("530 5.7.0 authentication required\r\n");
                    continue;
                }
                // The null reverse-path (bounces, RFC 5321 §4.5.5) is always accepted.
                if (path.len != 0) {
                    const addr = address.parse(path) catch {
                        try w.writeAll("501 5.1.7 bad sender address\r\n");
                        continue;
                    };
                    const hosted = catalog.find(addr.domain);
                    if (auth_identity) |identity| {
                        // Authenticated users may only send as themselves.
                        const own = hosted != null and std.mem.eql(u8, hosted.?.domain, identity.domain) and
                            std.ascii.eqlIgnoreCase(addr.user, identity.user);
                        if (!own) {
                            try w.writeAll("553 5.7.1 sender not authorized\r\n");
                            continue;
                        }
                    } else if (hosted != null) {
                        try w.writeAll("530 5.7.0 authentication required\r\n");
                        continue;
                    }
                }
                tx.sender = try allocator.dupe(u8, path);
                try w.writeAll("250 2.1.0 ok\r\n");
            } else if (std.ascii.eqlIgnoreCase(verb, "RCPT")) {
                if (tx.sender == null) {
                    try w.writeAll("503 5.5.1 need MAIL first\r\n");
                    continue;
                }
                const path, const params = splitPath(afterPrefix(args, "TO:") orelse {
                    try w.writeAll("501 5.5.4 syntax: RCPT TO:<address>\r\n");
                    continue;
                });
                if (params.len != 0) {
                    try w.writeAll("555 5.5.4 unsupported RCPT parameter\r\n");
                    continue;
                }
                const addr = address.parse(path) catch {
                    try w.writeAll("501 5.1.3 bad recipient address\r\n");
                    continue;
                };
                if (tx.recipients.items.len + tx.remote.items.len >= max_recipients) {
                    try w.writeAll("452 4.5.3 too many recipients\r\n");
                    continue;
                }
                const recipient = account_index.resolveMailbox(allocator, fs_io, self.storage, catalog, addr) catch |err| switch (err) {
                    error.NotHosted => {
                        // Only authenticated users may relay: otherwise this would be an open relay.
                        if (auth_identity == null) {
                            try w.writeAll("550 5.7.1 relaying denied\r\n");
                            continue;
                        }
                        const remote = try allocator.dupe(u8, path);
                        errdefer allocator.free(remote);
                        try tx.remote.append(allocator, remote);
                        try w.writeAll("250 2.1.5 ok\r\n");
                        continue;
                    },
                    error.UnknownUser => {
                        try w.writeAll("550 5.1.1 user unknown\r\n");
                        continue;
                    },
                    else => return err,
                };
                if (tx.has(recipient)) {
                    recipient.deinit(allocator);
                } else {
                    errdefer recipient.deinit(allocator);
                    try tx.recipients.append(allocator, recipient);
                }
                try w.writeAll("250 2.1.5 ok\r\n");
            } else if (std.ascii.eqlIgnoreCase(verb, "DATA")) {
                if (tx.recipients.items.len == 0 and tx.remote.items.len == 0) {
                    try w.writeAll("503 5.5.1 need RCPT first\r\n");
                    continue;
                }
                try w.writeAll("354 end data with <CR><LF>.<CR><LF>\r\n");
                const data = try readData(allocator, r, self.config.max_message_size) orelse return;
                defer tx.reset(allocator);
                const message = switch (data) {
                    .too_big => {
                        try w.writeAll("552 5.3.4 message size exceeds limit\r\n");
                        continue;
                    },
                    .line_too_long => {
                        try w.writeAll("500 5.5.2 line too long\r\n");
                        continue;
                    },
                    .message => |message| message,
                };
                defer allocator.free(message);

                var id_bytes: [6]u8 = undefined;
                fs_io.random(&id_bytes);
                const trace: Trace = .{
                    .reverse_path = tx.sender.?,
                    .helo = helo.?,
                    .remote = client.remote,
                    .hostname = self.config.hostname,
                    // RFC 3848 protocol names.
                    .protocol = if (!extended) "SMTP" else if (client.secure and auth_identity != null) "ESMTPSA" else if (client.secure) "ESMTPS" else if (auth_identity != null) "ESMTPA" else "ESMTP",
                    .id = std.fmt.bytesToHex(id_bytes, .lower),
                    .seconds = @intCast(@divFloor(Io.Clock.real.now(fs_io).nanoseconds, std.time.ns_per_s)),
                };
                var header: Io.Writer.Allocating = .init(allocator);
                defer header.deinit();

                const delivered = for (tx.recipients.items) |recipient| {
                    header.clearRetainingCapacity();
                    try writeTrace(&header.writer, trace, recipient);
                    const name = self.storage.deliver(fs_io, allocator, recipient.tenant, recipient.domain, recipient.user, header.written(), message) catch |err| {
                        std.debug.print("delivery to {s}@{s} failed: {}\n", .{ recipient.user, recipient.domain, err });
                        break false;
                    };
                    defer allocator.free(name);
                    std.debug.print("delivered to {s}@{s} as {s}\n", .{ recipient.user, recipient.domain, name });
                } else true;
                const queued = tx.remote.items.len == 0 or queued: {
                    // One queue entry for every remote recipient; Return-Path is
                    // left for the final delivery (RFC 5321 §4.4).
                    header.clearRetainingCapacity();
                    // Only authenticated users relay, and only as themselves.
                    const signature = if (auth_identity) |identity| self.dkimSignature(fs_io, identity, message, trace.seconds) else null;
                    defer if (signature) |value| allocator.free(value);
                    if (signature) |value| try header.writer.writeAll(value);
                    try writeTrace(&header.writer, trace, null);
                    const id = self.storage.enqueue(fs_io, allocator, tx.sender.?, tx.remote.items, header.written(), message) catch |err| {
                        std.debug.print("queueing failed: {}\n", .{err});
                        break :queued false;
                    };
                    defer allocator.free(id);
                    std.debug.print("queued {s} for {d} remote recipient(s)\n", .{ id, tx.remote.items.len });
                    break :queued true;
                };
                // A temporary failure makes the client retry: a duplicate beats a lost message.
                try w.writeAll(if (delivered and queued) "250 2.0.0 ok\r\n" else "451 4.3.0 local error in processing\r\n");
            } else {
                try w.writeAll("500 5.5.2 command unrecognized\r\n");
            }
        }
    }
};

// RFC 5321 §4.5.3.1 limits; line lengths include the CRLF.
const max_command_line = 512;
const max_text_line = 1000;
const max_recipients = 100;

/// One mail transaction: MAIL, RCPT..., DATA.
const Transaction = struct {
    /// Reverse-path without brackets; empty for the null sender.
    sender: ?[]u8 = null,
    recipients: std.ArrayList(Identity) = .empty,
    /// Recipients on other domains, queued for delivery (authenticated only).
    remote: std.ArrayList([]u8) = .empty,

    fn has(self: *const Transaction, identity: Identity) bool {
        for (self.recipients.items) |r| {
            if (std.mem.eql(u8, r.tenant, identity.tenant) and std.mem.eql(u8, r.domain, identity.domain) and std.mem.eql(u8, r.user, identity.user)) return true;
        }
        return false;
    }

    fn reset(self: *Transaction, allocator: std.mem.Allocator) void {
        if (self.sender) |sender| allocator.free(sender);
        self.sender = null;
        for (self.recipients.items) |r| r.deinit(allocator);
        self.recipients.clearRetainingCapacity();
        for (self.remote.items) |r| allocator.free(r);
        self.remote.clearRetainingCapacity();
    }

    fn deinit(self: *Transaction, allocator: std.mem.Allocator) void {
        self.reset(allocator);
        self.recipients.deinit(allocator);
        self.remote.deinit(allocator);
    }
};

/// Facts for the trace headers of one transaction.
const Trace = struct {
    reverse_path: []const u8,
    helo: []const u8,
    remote: ?std.Io.net.IpAddress,
    hostname: []const u8,
    protocol: []const u8,
    id: [12]u8,
    seconds: u64,
};

/// Return-Path and Received headers (RFC 5321 §4.4) for one locally
/// delivered copy, or only Received (without `for`) for queued mail.
fn writeTrace(w: *Io.Writer, t: Trace, recipient: ?Identity) !void {
    if (recipient != null) try w.print("Return-Path: <{s}>\r\n", .{t.reverse_path});
    try w.writeAll("Received: from ");
    // The HELO name is client-supplied: keep only printable characters.
    for (t.helo) |ch| try w.writeByte(if (std.ascii.isPrint(ch) and ch != '(' and ch != ')') ch else '?');
    if (t.remote) |ip| switch (ip) {
        .ip4 => |a| try w.print(" ([{d}.{d}.{d}.{d}])", .{ a.bytes[0], a.bytes[1], a.bytes[2], a.bytes[3] }),
        .ip6 => |a| try w.print(" ([IPv6:{f}])", .{std.Io.net.Ip6Address.Unresolved{ .bytes = a.bytes, .interface_name = null }}),
    };
    try w.print("\r\n\tby {s} with {s} id {s}", .{ t.hostname, t.protocol, &t.id });
    if (recipient) |r| try w.print("\r\n\tfor <{s}@{s}>", .{ r.user, r.domain });
    try w.writeAll("; ");
    try writeDate(w, t.seconds);
    try w.writeAll("\r\n");
}

/// RFC 5322 date-time in UTC, e.g. `Sat, 07 Nov 2026 09:15:47 +0000`.
pub fn writeDate(w: *Io.Writer, seconds: u64) !void {
    const epoch: std.time.epoch.EpochSeconds = .{ .secs = seconds };
    const day = epoch.getEpochDay();
    const year_day = day.calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    const time = epoch.getDaySeconds();
    const weekdays = [_][]const u8{ "Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed" }; // 1970-01-01 was a Thursday
    const months = [_][]const u8{ "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
    try w.print("{s}, {d:0>2} {s} {d} {d:0>2}:{d:0>2}:{d:0>2} +0000", .{
        weekdays[day.day % 7],
        @as(u8, month_day.day_index) + 1,
        months[@backingInt(month_day.month) - 1],
        year_day.year,
        time.getHoursIntoDay(),
        time.getMinutesIntoHour(),
        time.getSecondsIntoMinute(),
    });
}

fn isTransactionVerb(verb: []const u8) bool {
    for ([_][]const u8{ "MAIL", "RCPT", "DATA", "AUTH" }) |name| {
        if (std.ascii.eqlIgnoreCase(verb, name)) return true;
    }
    return false;
}

fn splitVerb(line: []const u8) struct { []const u8, []const u8 } {
    const end = std.mem.indexOfScalar(u8, line, ' ') orelse line.len;
    return .{ line[0..end], std.mem.trim(u8, line[end..], " ") };
}

fn afterPrefix(text: []const u8, prefix: []const u8) ?[]const u8 {
    if (text.len < prefix.len or !std.ascii.eqlIgnoreCase(text[0..prefix.len], prefix)) return null;
    return std.mem.trim(u8, text[prefix.len..], " ");
}

/// Splits `<path> params` (brackets optional, for lenient clients).
fn splitPath(text: []const u8) struct { []const u8, []const u8 } {
    if (text.len > 0 and text[0] == '<') {
        const close = std.mem.indexOfScalar(u8, text, '>') orelse return .{ text, "" };
        return .{ text[1..close], std.mem.trim(u8, text[close + 1 ..], " ") };
    }
    const end = std.mem.indexOfScalar(u8, text, ' ') orelse text.len;
    return .{ text[0..end], std.mem.trim(u8, text[end..], " ") };
}

/// Supported MAIL parameters: SIZE (RFC 1870), BODY (RFC 6152), AUTH
/// (RFC 4954, accepted and ignored). Returns the declared size.
fn parseMailParams(params: []const u8) !?u64 {
    var size: ?u64 = null;
    var it = std.mem.tokenizeScalar(u8, params, ' ');
    while (it.next()) |param| {
        if (afterPrefix(param, "SIZE=")) |value| {
            size = std.fmt.parseInt(u64, value, 10) catch return error.UnsupportedParameter;
        } else if (std.ascii.eqlIgnoreCase(param, "BODY=7BIT") or std.ascii.eqlIgnoreCase(param, "BODY=8BITMIME") or afterPrefix(param, "AUTH=") != null) {
            continue;
        } else return error.UnsupportedParameter;
    }
    return size;
}

const Line = union(enum) { line: []const u8, too_long };

/// Reads one line without its line ending. A line that does not fit in the
/// reader's buffer is consumed and reported as `too_long`.
fn readLine(r: *Io.Reader) !?Line {
    const raw = r.takeDelimiter('\n') catch |err| switch (err) {
        error.StreamTooLong => {
            _ = r.discardDelimiterInclusive('\n') catch |e| switch (e) {
                error.EndOfStream => return null,
                else => return e,
            };
            return .too_long;
        },
        else => return err,
    } orelse return null;
    return .{ .line = trimCr(raw) };
}

const Data = union(enum) { message: []u8, too_big, line_too_long };

/// Reads a DATA block up to the lone ".", undoing dot-stuffing. Oversized
/// input is drained, never buffered. Returns null if the client disconnects
/// mid-message (nothing gets delivered).
fn readData(allocator: std.mem.Allocator, r: *Io.Reader, max_size: u64) !?Data {
    var message = std.ArrayList(u8).empty;
    defer message.deinit(allocator);
    var failure: ?Data = null;

    while (true) {
        const line = switch (try readLine(r) orelse return null) {
            .too_long => {
                failure = failure orelse .line_too_long;
                continue;
            },
            .line => |line| line,
        };
        if (std.mem.eql(u8, line, ".")) break;
        if (failure != null) continue;
        if (line.len + 2 > max_text_line) {
            failure = .line_too_long;
            continue;
        }
        const content = if (line.len > 0 and line[0] == '.') line[1..] else line;
        if (message.items.len + content.len + 2 > max_size) {
            failure = .too_big;
            message.clearAndFree(allocator);
            continue;
        }
        try message.appendSlice(allocator, content);
        try message.appendSlice(allocator, "\r\n");
    }
    if (failure) |f| return f;
    return .{ .message = try message.toOwnedSlice(allocator) };
}

fn trimCr(line: []const u8) []const u8 {
    if (line.len > 0 and line[line.len - 1] == '\r') {
        return line[0 .. line.len - 1];
    }
    return line;
}

/// A data dir with tenant acme hosting example.com: account alice (password
/// "secret") and alias sales -> alice.
const TestDir = struct {
    tmp: std.testing.TmpDir,
    root: []u8,
    catalog: TenantCatalog,

    fn init(allocator: std.mem.Allocator) !TestDir {
        var tmp = std.testing.tmpDir(.{});
        errdefer tmp.cleanup();
        try account_index.writeTestAccounts(allocator, tmp.dir, &.{"alice"}, "secret");
        try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "tenants/acme/domains/example.com/aliases.txt", .data = "sales alice\n" });
        const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", tmp.sub_path[0..] });
        errdefer allocator.free(root);
        return .{ .tmp = tmp, .root = root, .catalog = try TenantIndex.parseForTest(allocator, "tenant acme example.com\n") };
    }

    fn deinit(self: *TestDir, allocator: std.mem.Allocator) void {
        self.catalog.deinit(allocator);
        allocator.free(self.root);
        self.tmp.cleanup();
    }

    /// Runs one SMTP session and returns the transcript; the caller frees it.
    /// Runs a session as if over TLS, so AUTH is available.
    fn session(self: *TestDir, allocator: std.mem.Allocator, input: []const u8) ![]u8 {
        return self.sessionWith(allocator, .{ .data_dir = self.root }, true, input);
    }

    fn sessionWith(self: *TestDir, allocator: std.mem.Allocator, config: Config, secure: bool, input: []const u8) ![]u8 {
        var server = Server.init(allocator, config, &self.catalog);
        var in: Io.Reader = .fixed(input);
        var out: Io.Writer.Allocating = .init(allocator);
        defer out.deinit();
        var client: conn.Client = .{ .reader = &in, .writer = &out.writer, .secure = secure };
        try server.handleClient(std.testing.io, &client);
        return out.toOwnedSlice();
    }

    fn inbox(self: *TestDir, allocator: std.mem.Allocator) ![]@import("storage.zig").Message {
        const path = try Storage.init(self.root).maildirPath(allocator, "acme", "example.com", "alice");
        defer allocator.free(path);
        return (try Storage.openMailbox(std.testing.io, allocator, path)).messages;
    }
};

test "resolveMailbox maps aliases, plus tags and case to the canonical account" {
    const allocator = std.testing.allocator;
    var dir = try TestDir.init(allocator);
    defer dir.deinit(allocator);
    const storage = Storage.init(dir.root);

    for ([_][]const u8{ "<alice@example.com>", "<Alice+news@EXAMPLE.com>", "<sales@example.com>", "<SALES+x@example.com>" }) |raw| {
        const identity = try account_index.resolveMailbox(allocator, std.testing.io, storage, &dir.catalog, try address.parse(raw));
        defer identity.deinit(allocator);
        try std.testing.expectEqualStrings("acme", identity.tenant);
        try std.testing.expectEqualStrings("example.com", identity.domain);
        try std.testing.expectEqualStrings("alice", identity.user);
    }
    try std.testing.expectError(error.UnknownUser, account_index.resolveMailbox(allocator, std.testing.io, storage, &dir.catalog, try address.parse("<bob@example.com>")));
    try std.testing.expectError(error.NotHosted, account_index.resolveMailbox(allocator, std.testing.io, storage, &dir.catalog, try address.parse("<alice@other.com>")));
}

test "authenticatePlain authenticates and refuses impersonation" {
    const allocator = std.testing.allocator;
    var dir = try TestDir.init(allocator);
    defer dir.deinit(allocator);
    const storage = Storage.init(dir.root);

    const payload = try buildPlainAuthPayload(allocator, "", "alice@example.com", "secret");
    defer allocator.free(payload);
    const identity = try account_index.authenticatePlain(allocator, std.testing.io, storage, &dir.catalog, payload);
    defer identity.deinit(allocator);
    try std.testing.expectEqualStrings("alice", identity.user);

    for ([_][3][]const u8{
        .{ "", "alice@example.com", "wrong" },
        .{ "bob@example.com", "alice@example.com", "secret" },
    }) |attempt| {
        const bad = try buildPlainAuthPayload(allocator, attempt[0], attempt[1], attempt[2]);
        defer allocator.free(bad);
        try std.testing.expectError(error.AuthFailed, account_index.authenticatePlain(allocator, std.testing.io, storage, &dir.catalog, bad));
    }
}

fn buildPlainAuthPayload(allocator: std.mem.Allocator, authzid: []const u8, login: []const u8, password: []const u8) ![]u8 {
    const raw = try std.mem.concat(allocator, u8, &.{ authzid, "\x00", login, "\x00", password });
    defer allocator.free(raw);
    const encoded = try allocator.alloc(u8, std.base64.standard.Encoder.calcSize(raw.len));
    _ = std.base64.standard.Encoder.encode(encoded, raw);
    return encoded;
}

const greeting = "220 localhost ESMTP raven ready\r\n";
const ehlo_reply = "250-localhost\r\n250-PIPELINING\r\n250-SIZE 26214400\r\n250-8BITMIME\r\n250-AUTH PLAIN\r\n250 ENHANCEDSTATUSCODES\r\n";

test "smtp session delivers a pipelined transaction" {
    const allocator = std.testing.allocator;
    var dir = try TestDir.init(allocator);
    defer dir.deinit(allocator);

    const transcript = try dir.session(allocator, "EHLO client\r\nMAIL FROM:<bob@external.test> SIZE=30 BODY=8BITMIME\r\n" ++
        "RCPT TO:<alice+news@example.com>\r\nRCPT TO:<sales@example.com>\r\n" ++
        "DATA\r\nSubject: hi\r\n\r\n..dot\r\n.\r\nQUIT\r\n");
    defer allocator.free(transcript);
    try std.testing.expectEqualStrings(greeting ++ ehlo_reply ++
        "250 2.1.0 ok\r\n250 2.1.5 ok\r\n250 2.1.5 ok\r\n354 end data with <CR><LF>.<CR><LF>\r\n250 2.0.0 ok\r\n221 2.0.0 bye\r\n", transcript);

    // sales is an alias of alice: one copy, not two.
    const messages = try dir.inbox(allocator);
    defer @import("storage.zig").freeMessages(allocator, messages);
    try std.testing.expectEqual(@as(usize, 1), messages.len);
    const body = try Storage.readMessage(std.testing.io, allocator, messages[0]);
    defer allocator.free(body);
    try std.testing.expectStringStartsWith(body, "Return-Path: <bob@external.test>\r\nReceived: from client\r\n\tby localhost with ESMTPS id ");
    try std.testing.expect(std.mem.indexOf(u8, body, "\r\n\tfor <alice@example.com>; ") != null);
    try std.testing.expectStringEndsWith(body, " +0000\r\nSubject: hi\r\n\r\n.dot\r\n");
}

test "dates are RFC 5322" {
    for ([_]struct { u64, []const u8 }{
        .{ 0, "Thu, 01 Jan 1970 00:00:00 +0000" },
        .{ 951782400, "Tue, 29 Feb 2000 00:00:00 +0000" },
        .{ 1794044147, "Sat, 07 Nov 2026 09:35:47 +0000" },
        .{ 4102444799, "Thu, 31 Dec 2099 23:59:59 +0000" },
    }) |case| {
        var buf: [64]u8 = undefined;
        var w: Io.Writer = .fixed(&buf);
        try writeDate(&w, case[0]);
        try std.testing.expectEqualStrings(case[1], w.buffered());
    }
}

test "trace headers record sender, client and recipient" {
    const allocator = std.testing.allocator;
    const recipient = try Identity.init(allocator, "acme", "example.com", "alice");
    defer recipient.deinit(allocator);

    var out: Io.Writer.Allocating = .init(allocator);
    defer out.deinit();
    var trace: Trace = .{
        .reverse_path = "",
        .helo = "evil\x01(host)",
        .remote = try std.Io.net.IpAddress.parse("192.0.2.7", 25),
        .hostname = "mx.example.com",
        .protocol = "ESMTPSA",
        .id = "0123456789ab".*,
        .seconds = 1794044147,
    };
    try writeTrace(&out.writer, trace, recipient);
    try std.testing.expectEqualStrings("Return-Path: <>\r\nReceived: from evil??host? ([192.0.2.7])\r\n" ++
        "\tby mx.example.com with ESMTPSA id 0123456789ab\r\n\tfor <alice@example.com>; Sat, 07 Nov 2026 09:35:47 +0000\r\n", out.written());

    out.clearRetainingCapacity();
    trace.remote = try std.Io.net.IpAddress.parse("2001:db8::1", 25);
    try writeTrace(&out.writer, trace, recipient);
    try std.testing.expect(std.mem.indexOf(u8, out.written(), " ([IPv6:2001:db8::1])\r\n") != null);
}

test "smtp session accepts the null sender" {
    const allocator = std.testing.allocator;
    var dir = try TestDir.init(allocator);
    defer dir.deinit(allocator);

    const transcript = try dir.session(allocator, "HELO client\r\nMAIL FROM:<>\r\nRCPT TO:<alice@example.com>\r\nDATA\r\nbounce\r\n.\r\nQUIT\r\n");
    defer allocator.free(transcript);
    try std.testing.expectEqualStrings(greeting ++ "250 localhost\r\n250 2.1.0 ok\r\n250 2.1.5 ok\r\n" ++
        "354 end data with <CR><LF>.<CR><LF>\r\n250 2.0.0 ok\r\n221 2.0.0 bye\r\n", transcript);
}

test "smtp session enforces command order and syntax" {
    const allocator = std.testing.allocator;
    var dir = try TestDir.init(allocator);
    defer dir.deinit(allocator);

    const transcript = try dir.session(allocator, "MAIL FROM:<bob@external.test>\r\nEHLO\r\nVRFY alice\r\nBOGUS\r\nEHLO client\r\n" ++
        "RCPT TO:<alice@example.com>\r\nDATA\r\nMAIL bob@external.test\r\nMAIL FROM:bob@external.test\r\n" ++
        "MAIL FROM:<carol@external.test>\r\nRCPT TO:<alice@example.com> NOTIFY=NEVER\r\nRSET\r\n" ++
        "MAIL FROM:<bob@external.test> FOO=1\r\nQUIT\r\n");
    defer allocator.free(transcript);
    try std.testing.expectEqualStrings(greeting ++
        "503 5.5.1 send EHLO first\r\n501 5.5.4 syntax: EHLO hostname\r\n252 2.5.0 cannot verify, but will attempt delivery\r\n" ++
        "500 5.5.2 command unrecognized\r\n" ++ ehlo_reply ++
        "503 5.5.1 need MAIL first\r\n503 5.5.1 need RCPT first\r\n501 5.5.4 syntax: MAIL FROM:<address>\r\n250 2.1.0 ok\r\n" ++
        "503 5.5.1 nested MAIL command\r\n555 5.5.4 unsupported RCPT parameter\r\n250 2.0.0 ok\r\n" ++
        "555 5.5.4 unsupported MAIL parameter\r\n221 2.0.0 bye\r\n", transcript);
}

test "smtp session enforces size and line limits" {
    const allocator = std.testing.allocator;
    var dir = try TestDir.init(allocator);
    defer dir.deinit(allocator);

    const long_command = "NOOP " ++ @as([600]u8, @splat('x')) ++ "\r\n";
    const long_text = @as([999]u8, @splat('y')) ++ "\r\n";
    const transcript = try dir.sessionWith(allocator, .{ .data_dir = dir.root, .max_message_size = 64 }, true, "EHLO client\r\n" ++ long_command ++
        "MAIL FROM:<bob@external.test> SIZE=65\r\n" ++
        "MAIL FROM:<bob@external.test>\r\nRCPT TO:<alice@example.com>\r\nDATA\r\n" ++ @as([70]u8, @splat('z')) ++ "\r\n.\r\n" ++
        "MAIL FROM:<bob@external.test>\r\nRCPT TO:<alice@example.com>\r\nDATA\r\n" ++ long_text ++ ".\r\nQUIT\r\n");
    defer allocator.free(transcript);
    try std.testing.expectEqualStrings(greeting ++
        "250-localhost\r\n250-PIPELINING\r\n250-SIZE 64\r\n250-8BITMIME\r\n250-AUTH PLAIN\r\n250 ENHANCEDSTATUSCODES\r\n" ++
        "500 5.5.2 line too long\r\n552 5.3.4 message size exceeds limit\r\n" ++
        "250 2.1.0 ok\r\n250 2.1.5 ok\r\n354 end data with <CR><LF>.<CR><LF>\r\n552 5.3.4 message size exceeds limit\r\n" ++
        "250 2.1.0 ok\r\n250 2.1.5 ok\r\n354 end data with <CR><LF>.<CR><LF>\r\n500 5.5.2 line too long\r\n221 2.0.0 bye\r\n", transcript);

    const messages = try dir.inbox(allocator);
    defer @import("storage.zig").freeMessages(allocator, messages);
    try std.testing.expectEqual(@as(usize, 0), messages.len);
}

test "smtp session caps recipients per transaction" {
    const allocator = std.testing.allocator;
    var dir = try TestDir.init(allocator);
    defer dir.deinit(allocator);

    var users: [max_recipients + 1][]const u8 = undefined;
    var names: [max_recipients + 1][8]u8 = undefined;
    var input: std.Io.Writer.Allocating = .init(allocator);
    defer input.deinit();
    try input.writer.writeAll("EHLO client\r\nMAIL FROM:<bob@external.test>\r\n");
    for (&users, &names, 0..) |*user, *name, i| {
        user.* = try std.fmt.bufPrint(name, "u{d}", .{i});
        try input.writer.print("RCPT TO:<{s}@example.com>\r\n", .{user.*});
    }
    try account_index.writeTestAccounts(allocator, dir.tmp.dir, &users, "secret");

    const transcript = try dir.session(allocator, input.written());
    defer allocator.free(transcript);
    try std.testing.expectEqual(@as(usize, max_recipients), std.mem.count(u8, transcript, "250 2.1.5 ok\r\n"));
    try std.testing.expect(std.mem.endsWith(u8, transcript, "452 4.5.3 too many recipients\r\n"));
}

test "smtp session enforces relay, recipient and sender rules" {
    const allocator = std.testing.allocator;
    var dir = try TestDir.init(allocator);
    defer dir.deinit(allocator);

    const auth = try buildPlainAuthPayload(allocator, "", "alice@example.com", "secret");
    defer allocator.free(auth);
    const input = try std.mem.concat(allocator, u8, &.{
        "EHLO client\r\n",
        "MAIL FROM:<alice@example.com>\r\n", // hosted sender without auth
        "MAIL FROM:<bob@external.test>\r\n",
        "RCPT TO:<alice@other.com>\r\n", // not hosted: no relaying
        "RCPT TO:<nobody@example.com>\r\n",
        "RSET\r\nAUTH PLAIN ",
        auth,
        "\r\nAUTH PLAIN\r\n",
        "MAIL FROM:<bob@example.com>\r\n", // authenticated, but not as bob
        "MAIL FROM:<Alice@example.com>\r\nQUIT\r\n",
    });
    defer allocator.free(input);

    const transcript = try dir.session(allocator, input);
    defer allocator.free(transcript);
    try std.testing.expectEqualStrings(greeting ++ ehlo_reply ++
        "530 5.7.0 authentication required\r\n250 2.1.0 ok\r\n550 5.7.1 relaying denied\r\n550 5.1.1 user unknown\r\n250 2.0.0 ok\r\n" ++
        "235 2.7.0 authentication successful\r\n503 5.5.1 already authenticated\r\n553 5.7.1 sender not authorized\r\n" ++
        "250 2.1.0 ok\r\n221 2.0.0 bye\r\n", transcript);
}

test "smtp session refuses AUTH over plaintext unless allowed" {
    const allocator = std.testing.allocator;
    var dir = try TestDir.init(allocator);
    defer dir.deinit(allocator);

    const plain = try dir.sessionWith(allocator, .{ .data_dir = dir.root }, false, "EHLO client\r\nAUTH PLAIN\r\nSTARTTLS\r\nQUIT\r\n");
    defer allocator.free(plain);
    try std.testing.expectEqualStrings(greeting ++ "250-localhost\r\n250-PIPELINING\r\n250-SIZE 26214400\r\n250-8BITMIME\r\n250 ENHANCEDSTATUSCODES\r\n" ++
        "538 5.7.11 encryption required for authentication\r\n454 4.7.0 TLS not available\r\n221 2.0.0 bye\r\n", plain);

    const opted_out = try dir.sessionWith(allocator, .{ .data_dir = dir.root, .allow_plaintext_auth = true }, false, "EHLO client\r\nAUTH PLAIN\r\n*\r\nQUIT\r\n");
    defer allocator.free(opted_out);
    try std.testing.expectEqualStrings(greeting ++ ehlo_reply ++ "334 \r\n501 5.0.0 authentication canceled\r\n221 2.0.0 bye\r\n", opted_out);
}

test "smtp session handles AUTH continuation and cancel" {
    const allocator = std.testing.allocator;
    var dir = try TestDir.init(allocator);
    defer dir.deinit(allocator);

    const wrong = try buildPlainAuthPayload(allocator, "", "alice@example.com", "wrong");
    defer allocator.free(wrong);
    const input = try std.mem.concat(allocator, u8, &.{ "EHLO client\r\nAUTH LOGIN\r\nAUTH PLAIN\r\n*\r\nAUTH PLAIN\r\n", wrong, "\r\nQUIT\r\n" });
    defer allocator.free(input);

    const transcript = try dir.session(allocator, input);
    defer allocator.free(transcript);
    try std.testing.expectEqualStrings(greeting ++ ehlo_reply ++
        "504 5.5.4 mechanism not supported\r\n334 \r\n501 5.0.0 authentication canceled\r\n334 \r\n535 5.7.8 authentication failed\r\n221 2.0.0 bye\r\n", transcript);
}

test "smtp session rejects path traversal in addresses" {
    const allocator = std.testing.allocator;
    var dir = try TestDir.init(allocator);
    defer dir.deinit(allocator);

    const transcript = try dir.session(allocator, "EHLO client\r\nMAIL FROM:<../../x@external.test>\r\nMAIL FROM:<bob@external.test>\r\n" ++
        "RCPT TO:<../../../../../escape@example.com>\r\nRCPT TO:<alice@../../../escape>\r\nDATA\r\nQUIT\r\n");
    defer allocator.free(transcript);
    try std.testing.expectEqualStrings(greeting ++ ehlo_reply ++ "501 5.1.7 bad sender address\r\n250 2.1.0 ok\r\n" ++
        "501 5.1.3 bad recipient address\r\n501 5.1.3 bad recipient address\r\n503 5.5.1 need RCPT first\r\n221 2.0.0 bye\r\n", transcript);
    try std.testing.expectError(error.FileNotFound, dir.tmp.dir.access(std.testing.io, "escape", .{}));
}

test "authenticated users relay through the queue; local copies are delivered" {
    const allocator = std.testing.allocator;
    var dir = try TestDir.init(allocator);
    defer dir.deinit(allocator);

    const auth = try buildPlainAuthPayload(allocator, "", "alice@example.com", "secret");
    defer allocator.free(auth);
    const input = try std.mem.concat(allocator, u8, &.{ "EHLO client\r\nAUTH PLAIN ", auth, "\r\nMAIL FROM:<alice@example.com>\r\n" ++
        "RCPT TO:<bob@remote.test>\r\nRCPT TO:<carol+x@other.test>\r\nRCPT TO:<sales@example.com>\r\nDATA\r\nSubject: out\r\n\r\nhi\r\n.\r\nQUIT\r\n" });
    defer allocator.free(input);
    const transcript = try dir.session(allocator, input);
    defer allocator.free(transcript);
    try std.testing.expectStringEndsWith(transcript, "250 2.1.0 ok\r\n250 2.1.5 ok\r\n250 2.1.5 ok\r\n250 2.1.5 ok\r\n" ++
        "354 end data with <CR><LF>.<CR><LF>\r\n250 2.0.0 ok\r\n221 2.0.0 bye\r\n");

    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const entries = try Storage.init(dir.root).listQueue(std.testing.io, arena_state.allocator());
    try std.testing.expectEqual(@as(usize, 1), entries.len);
    try std.testing.expectEqualStrings("alice@example.com", entries[0].sender);
    try std.testing.expectEqual(@as(usize, 2), entries[0].recipients.len);
    try std.testing.expectEqualStrings("bob@remote.test", entries[0].recipients[0]);
    try std.testing.expectEqualStrings("carol+x@other.test", entries[0].recipients[1]);

    const queued_path = try std.fmt.allocPrint(allocator, "queue/outbound/{s}.eml", .{entries[0].id});
    defer allocator.free(queued_path);
    const queued = try dir.tmp.dir.readFileAlloc(std.testing.io, queued_path, allocator, .limited(4096));
    defer allocator.free(queued);
    try std.testing.expectStringStartsWith(queued, "Received: from client\r\n\tby localhost with ESMTPSA id ");
    try std.testing.expect(std.mem.indexOf(u8, queued, "Return-Path") == null);
    try std.testing.expectStringEndsWith(queued, "Subject: out\r\n\r\nhi\r\n");

    const messages = try dir.inbox(allocator);
    defer @import("storage.zig").freeMessages(allocator, messages);
    try std.testing.expectEqual(@as(usize, 1), messages.len); // the local alias copy
}

test "the submission port requires AUTH before MAIL" {
    const allocator = std.testing.allocator;
    var dir = try TestDir.init(allocator);
    defer dir.deinit(allocator);

    var server = Server.init(allocator, .{ .data_dir = dir.root }, &dir.catalog);
    server.submission = true;
    var in: Io.Reader = .fixed("EHLO client\r\nMAIL FROM:<bob@external.test>\r\nQUIT\r\n");
    var out: Io.Writer.Allocating = .init(allocator);
    defer out.deinit();
    var client: conn.Client = .{ .reader = &in, .writer = &out.writer, .secure = true };
    try server.handleClient(std.testing.io, &client);
    try std.testing.expectStringEndsWith(out.written(), "530 5.7.0 authentication required\r\n221 2.0.0 bye\r\n");
}

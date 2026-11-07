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

pub const Server = struct {
    allocator: std.mem.Allocator,
    config: Config,
    storage: Storage,
    tenant_catalog: *const TenantCatalog,

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

        var greeted = false;
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
                greeted = true;
                if (std.ascii.eqlIgnoreCase(verb, "HELO")) {
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
                greeted = false;
                tx.reset(allocator);
                if (auth_identity) |value| value.deinit(allocator);
                auth_identity = null;
            } else if (!greeted and isTransactionVerb(verb)) {
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
                auth_identity = completeAuthPlain(allocator, fs_io, self.storage, catalog, response) catch |err| switch (err) {
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
                if (tx.recipients.items.len >= max_recipients) {
                    try w.writeAll("452 4.5.3 too many recipients\r\n");
                    continue;
                }
                const recipient = resolveRecipient(allocator, fs_io, self.storage, catalog, addr) catch |err| switch (err) {
                    error.NotHosted => {
                        try w.writeAll("550 5.7.1 relaying denied\r\n");
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
                if (tx.recipients.items.len == 0) {
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

                for (tx.recipients.items) |recipient| {
                    const name = self.storage.deliver(fs_io, allocator, recipient.tenant, recipient.domain, recipient.user, message) catch |err| {
                        std.debug.print("delivery to {s}@{s} failed: {}\n", .{ recipient.user, recipient.domain, err });
                        // A temporary failure makes the client retry: a duplicate beats a lost message.
                        try w.writeAll("451 4.3.0 local error in processing\r\n");
                        break;
                    };
                    defer allocator.free(name);
                    std.debug.print("delivered to {s}@{s} as {s}\n", .{ recipient.user, recipient.domain, name });
                } else try w.writeAll("250 2.0.0 ok\r\n");
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
    }

    fn deinit(self: *Transaction, allocator: std.mem.Allocator) void {
        self.reset(allocator);
        self.recipients.deinit(allocator);
    }
};

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

/// RFC 4616 PLAIN: base64("authzid\0authcid\0password").
fn completeAuthPlain(allocator: std.mem.Allocator, io: Io, storage: Storage, catalog: *const TenantCatalog, encoded: []const u8) !Identity {
    const decoded = try decodeBase64Payload(allocator, std.mem.trim(u8, encoded, " \t"));
    defer allocator.free(decoded);

    var fields = std.mem.splitScalar(u8, decoded, 0);
    const authzid = fields.next() orelse return error.AuthFailed;
    const login = fields.next() orelse return error.AuthFailed;
    const password = fields.next() orelse return error.AuthFailed;
    if (fields.next() != null or password.len == 0) return error.AuthFailed;
    // Acting as another user is not supported.
    if (authzid.len != 0 and !std.ascii.eqlIgnoreCase(authzid, login)) return error.AuthFailed;

    return account_index.authenticate(allocator, io, storage, catalog, login, password);
}

fn decodeBase64Payload(allocator: std.mem.Allocator, encoded: []const u8) ![]u8 {
    const clean = std.mem.trim(u8, encoded, " \t");
    const codecs = [_]std.base64.Codecs{ std.base64.standard, std.base64.standard_no_pad };

    for (codecs) |codec| {
        const decoder = &codec.Decoder;
        const size = decoder.calcSizeForSlice(clean) catch continue;
        const buf = try allocator.alloc(u8, size);
        decoder.decode(buf, clean) catch {
            allocator.free(buf);
            continue;
        };
        return buf;
    }
    return error.AuthFailed;
}

/// Maps a recipient address to a local mailbox: the domain must be hosted
/// and the user an account, directly or through an alias. `+tag` is ignored.
fn resolveRecipient(allocator: std.mem.Allocator, io: Io, storage: Storage, catalog: *const TenantCatalog, addr: address.Address) !Identity {
    const hosted = catalog.find(addr.domain) orelse return error.NotHosted;

    var aliases = try AliasTable.load(allocator, io, storage, hosted.tenant, hosted.domain);
    defer aliases.deinit(allocator);
    var accounts = try AccountStore.load(allocator, io, storage, hosted.tenant, hosted.domain);
    defer accounts.deinit(allocator);

    const account = accounts.find(aliases.find(addr.user) orelse addr.user) orelse return error.UnknownUser;
    return Identity.init(allocator, hosted.tenant, hosted.domain, account.user);
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
        return Storage.init(self.root).listMailbox(std.testing.io, allocator, "acme", "example.com", "alice");
    }
};

test "resolveRecipient maps aliases, plus tags and case to the canonical account" {
    const allocator = std.testing.allocator;
    var dir = try TestDir.init(allocator);
    defer dir.deinit(allocator);
    const storage = Storage.init(dir.root);

    for ([_][]const u8{ "<alice@example.com>", "<Alice+news@EXAMPLE.com>", "<sales@example.com>", "<SALES+x@example.com>" }) |raw| {
        const identity = try resolveRecipient(allocator, std.testing.io, storage, &dir.catalog, try address.parse(raw));
        defer identity.deinit(allocator);
        try std.testing.expectEqualStrings("acme", identity.tenant);
        try std.testing.expectEqualStrings("example.com", identity.domain);
        try std.testing.expectEqualStrings("alice", identity.user);
    }
    try std.testing.expectError(error.UnknownUser, resolveRecipient(allocator, std.testing.io, storage, &dir.catalog, try address.parse("<bob@example.com>")));
    try std.testing.expectError(error.NotHosted, resolveRecipient(allocator, std.testing.io, storage, &dir.catalog, try address.parse("<alice@other.com>")));
}

test "completeAuthPlain authenticates and refuses impersonation" {
    const allocator = std.testing.allocator;
    var dir = try TestDir.init(allocator);
    defer dir.deinit(allocator);
    const storage = Storage.init(dir.root);

    const payload = try buildPlainAuthPayload(allocator, "", "alice@example.com", "secret");
    defer allocator.free(payload);
    const identity = try completeAuthPlain(allocator, std.testing.io, storage, &dir.catalog, payload);
    defer identity.deinit(allocator);
    try std.testing.expectEqualStrings("alice", identity.user);

    for ([_][3][]const u8{
        .{ "", "alice@example.com", "wrong" },
        .{ "bob@example.com", "alice@example.com", "secret" },
    }) |attempt| {
        const bad = try buildPlainAuthPayload(allocator, attempt[0], attempt[1], attempt[2]);
        defer allocator.free(bad);
        try std.testing.expectError(error.AuthFailed, completeAuthPlain(allocator, std.testing.io, storage, &dir.catalog, bad));
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
    try std.testing.expectEqualStrings("Subject: hi\r\n\r\n.dot\r\n", body);
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

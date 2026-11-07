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

    pub fn listen(self: *Server, io: Io) !std.Io.net.Server {
        const ip = try std.Io.net.IpAddress.parse(self.config.listen_address, self.config.listen_port);
        const listener = try ip.listen(io, .{ .reuse_address = true });
        std.debug.print("smtp listening on {any}\n", .{ip});
        return listener;
    }

    pub fn handleClient(self: *Server, fs_io: Io, r: *Io.Reader, w: *Io.Writer) !void {
        const tenant_catalog = self.tenant_catalog;
        try w.writeAll("220 ");
        try w.writeAll(self.config.hostname);
        try w.writeAll(" ESMTP raven ready\r\n");

        var sender: ?[]u8 = null;
        defer if (sender) |value| self.allocator.free(value);

        var auth_identity: ?Identity = null;
        defer if (auth_identity) |value| value.deinit(self.allocator);

        var auth_pending: ?AuthChallenge = null;

        var recipients = std.ArrayList(Identity).empty;
        defer {
            clearRecipients(self.allocator, &recipients);
            recipients.deinit(self.allocator);
        }

        while (true) {
            const line = try nextLine(r) orelse return;

            if (auth_pending != null) {
                auth_pending = null;
                const identity = completeAuthPlain(self.allocator, fs_io, self.storage, tenant_catalog, line) catch {
                    try w.writeAll("535 5.7.8 Authentication failed\r\n");
                    continue;
                };

                if (auth_identity) |value| value.deinit(self.allocator);
                auth_identity = identity;
                try w.writeAll("235 2.7.0 Authentication successful\r\n");
                continue;
            }

            if (startsWithIgnoreCase(line, "QUIT")) {
                try w.writeAll("221 bye\r\n");
                return;
            }

            if (startsWithIgnoreCase(line, "EHLO") or startsWithIgnoreCase(line, "HELO")) {
                try w.writeAll("250-");
                try w.writeAll(self.config.hostname);
                try w.writeAll("\r\n250-AUTH PLAIN\r\n250 PIPELINING\r\n");
                continue;
            }

            if (startsWithIgnoreCase(line, "NOOP")) {
                try w.writeAll("250 ok\r\n");
                continue;
            }

            if (startsWithIgnoreCase(line, "AUTH ")) {
                const auth = parseAuthCommand(line) catch {
                    try w.writeAll("501 bad auth command\r\n");
                    continue;
                };

                if (!std.ascii.eqlIgnoreCase(auth.mechanism, "PLAIN")) {
                    try w.writeAll("504 mechanism unsupported\r\n");
                    continue;
                }

                if (auth.initial_response) |response| {
                    const identity = completeAuthPlain(self.allocator, fs_io, self.storage, tenant_catalog, response) catch {
                        try w.writeAll("535 5.7.8 Authentication failed\r\n");
                        continue;
                    };

                    if (auth_identity) |value| value.deinit(self.allocator);
                    auth_identity = identity;
                    try w.writeAll("235 2.7.0 Authentication successful\r\n");
                    continue;
                }

                auth_pending = .plain;
                try w.writeAll("334 \r\n");
                continue;
            }

            if (startsWithIgnoreCase(line, "RSET")) {
                if (sender) |value| self.allocator.free(value);
                sender = null;
                clearRecipients(self.allocator, &recipients);
                try w.writeAll("250 ok\r\n");
                continue;
            }

            if (startsWithIgnoreCase(line, "MAIL FROM:")) {
                const from = trimAfterColon(line);
                const addr = address.parse(from) catch {
                    try w.writeAll("501 bad sender\r\n");
                    continue;
                };

                const hosted = tenant_catalog.find(addr.domain);
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

                const new_sender = try self.allocator.dupe(u8, from);
                if (sender) |value| self.allocator.free(value);
                sender = new_sender;
                clearRecipients(self.allocator, &recipients);
                try w.writeAll("250 ok\r\n");
                continue;
            }

            if (startsWithIgnoreCase(line, "RCPT TO:")) {
                if (sender == null) {
                    try w.writeAll("503 need mail first\r\n");
                    continue;
                }

                const addr = address.parse(trimAfterColon(line)) catch {
                    try w.writeAll("501 bad recipient\r\n");
                    continue;
                };

                const recipient = resolveRecipient(self.allocator, fs_io, self.storage, tenant_catalog, addr) catch |err| switch (err) {
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
                errdefer recipient.deinit(self.allocator);

                try recipients.append(self.allocator, recipient);
                try w.writeAll("250 ok\r\n");
                continue;
            }

            if (startsWithIgnoreCase(line, "DATA")) {
                if (recipients.items.len == 0) {
                    try w.writeAll("503 need rcpt first\r\n");
                    continue;
                }

                try w.writeAll("354 end with <CR><LF>.<CR><LF>\r\n");
                const message = try readDataBlock(self.allocator, r);
                defer self.allocator.free(message);

                const delivered = for (recipients.items) |recipient| {
                    const name = self.storage.deliver(fs_io, self.allocator, recipient.tenant, recipient.domain, recipient.user, message) catch |err| {
                        std.debug.print("delivery to {s}@{s} failed: {}\n", .{ recipient.user, recipient.domain, err });
                        break false;
                    };
                    defer self.allocator.free(name);
                    std.debug.print("delivered to {s}@{s} as {s}\n", .{ recipient.user, recipient.domain, name });
                } else true;

                if (sender) |value| self.allocator.free(value);
                sender = null;
                clearRecipients(self.allocator, &recipients);
                // A temporary failure makes the client retry: a duplicate beats a lost message.
                if (!delivered) {
                    try w.writeAll("451 4.3.0 local error in processing\r\n");
                    continue;
                }
                try w.writeAll("250 queued\r\n");
                continue;
            }

            try w.writeAll("502 command not implemented\r\n");
        }
    }
};

const AuthChallenge = enum { plain };

const AuthCommand = struct {
    mechanism: []const u8,
    initial_response: ?[]const u8,
};

fn parseAuthCommand(line: []const u8) !AuthCommand {
    const after_auth = std.mem.trim(u8, line[4..], " \t");
    var parts = std.mem.tokenizeAny(u8, after_auth, " \t");
    const mechanism = parts.next() orelse return error.InvalidAuth;
    return .{ .mechanism = mechanism, .initial_response = parts.next() };
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

fn nextLine(reader: *Io.Reader) !?[]const u8 {
    const line = try reader.takeDelimiter('\n') orelse return null;

    return trimCr(line);
}

fn readDataBlock(allocator: std.mem.Allocator, reader: *Io.Reader) ![]u8 {
    var message = std.ArrayList(u8).empty;
    errdefer message.deinit(allocator);

    while (true) {
        const line = try nextLine(reader) orelse break;

        if (std.mem.eql(u8, line, ".")) break;

        if (line.len > 0 and line[0] == '.') {
            try message.appendSlice(allocator, line[1..]);
        } else {
            try message.appendSlice(allocator, line);
        }
        try message.appendSlice(allocator, "\r\n");
    }

    return try message.toOwnedSlice(allocator);
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

fn clearRecipients(allocator: std.mem.Allocator, recipients: *std.ArrayList(Identity)) void {
    for (recipients.items) |recipient| recipient.deinit(allocator);
    recipients.clearRetainingCapacity();
}

fn startsWithIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    if (haystack.len < needle.len) return false;
    return std.ascii.eqlIgnoreCase(haystack[0..needle.len], needle);
}

fn trimAfterColon(line: []const u8) []const u8 {
    var index: usize = 0;
    while (index < line.len and line[index] != ':') : (index += 1) {}
    if (index >= line.len) return line;
    return std.mem.trim(u8, line[index + 1 ..], " \t");
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
        var hash_buf: [64]u8 = undefined;
        const accounts = try std.fmt.allocPrint(allocator, "alice {s}\n", .{account_index.passwordHashHex("secret", &hash_buf)});
        defer allocator.free(accounts);
        try tmp.dir.createDirPath(std.testing.io, "tenants/acme/domains/example.com");
        try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "tenants/acme/domains/example.com/accounts.txt", .data = accounts });
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
    fn session(self: *TestDir, allocator: std.mem.Allocator, input: []const u8) ![]u8 {
        var server = Server.init(allocator, .{ .data_dir = self.root }, &self.catalog);
        var in: Io.Reader = .fixed(input);
        var out: Io.Writer.Allocating = .init(allocator);
        defer out.deinit();
        try server.handleClient(std.testing.io, &in, &out.writer);
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

test "smtp session delivers a pipelined transaction" {
    const allocator = std.testing.allocator;
    var dir = try TestDir.init(allocator);
    defer dir.deinit(allocator);

    const transcript = try dir.session(allocator, "EHLO client\r\nMAIL FROM:<bob@external.test>\r\nRCPT TO:<alice+news@example.com>\r\n" ++
        "DATA\r\nSubject: hi\r\n\r\n..dot\r\n.\r\nQUIT\r\n");
    defer allocator.free(transcript);
    try std.testing.expectEqualStrings("220 localhost ESMTP raven ready\r\n" ++
        "250-localhost\r\n250-AUTH PLAIN\r\n250 PIPELINING\r\n" ++
        "250 ok\r\n250 ok\r\n354 end with <CR><LF>.<CR><LF>\r\n250 queued\r\n221 bye\r\n", transcript);

    const messages = try dir.inbox(allocator);
    defer @import("storage.zig").freeMessages(allocator, messages);
    try std.testing.expectEqual(@as(usize, 1), messages.len);
    const body = try Storage.readMessage(std.testing.io, allocator, messages[0]);
    defer allocator.free(body);
    try std.testing.expectEqualStrings("Subject: hi\r\n\r\n.dot\r\n", body);
}

test "smtp session enforces relay, recipient and sender rules" {
    const allocator = std.testing.allocator;
    var dir = try TestDir.init(allocator);
    defer dir.deinit(allocator);

    const auth = try buildPlainAuthPayload(allocator, "", "alice@example.com", "secret");
    defer allocator.free(auth);
    const input = try std.mem.concat(allocator, u8, &.{
        "MAIL FROM:<alice@example.com>\r\n", // hosted sender without auth
        "MAIL FROM:<bob@external.test>\r\n",
        "RCPT TO:<alice@other.com>\r\n", // not hosted: no relaying
        "RCPT TO:<nobody@example.com>\r\n",
        "AUTH PLAIN ",
        auth,
        "\r\nMAIL FROM:<bob@example.com>\r\n", // authenticated, but not as bob
        "MAIL FROM:<Alice@example.com>\r\nQUIT\r\n",
    });
    defer allocator.free(input);

    const transcript = try dir.session(allocator, input);
    defer allocator.free(transcript);
    try std.testing.expectEqualStrings("220 localhost ESMTP raven ready\r\n" ++
        "530 5.7.0 authentication required\r\n250 ok\r\n550 5.7.1 relaying denied\r\n550 5.1.1 user unknown\r\n" ++
        "235 2.7.0 Authentication successful\r\n553 5.7.1 sender not authorized\r\n250 ok\r\n221 bye\r\n", transcript);
}

test "smtp session rejects path traversal in addresses" {
    const allocator = std.testing.allocator;
    var dir = try TestDir.init(allocator);
    defer dir.deinit(allocator);

    const transcript = try dir.session(allocator, "MAIL FROM:<../../x@external.test>\r\nMAIL FROM:<bob@external.test>\r\n" ++
        "RCPT TO:<../../../../../escape@example.com>\r\nRCPT TO:<alice@../../../escape>\r\nDATA\r\nQUIT\r\n");
    defer allocator.free(transcript);
    try std.testing.expectEqualStrings("220 localhost ESMTP raven ready\r\n501 bad sender\r\n250 ok\r\n" ++
        "501 bad recipient\r\n501 bad recipient\r\n503 need rcpt first\r\n221 bye\r\n", transcript);
    try std.testing.expectError(error.FileNotFound, dir.tmp.dir.access(std.testing.io, "escape", .{}));
}

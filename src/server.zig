const std = @import("std");

const Io = std.Io;
const AccountStore = @import("account_index.zig").AccountStore;
const address = @import("address.zig");
const Config = @import("config.zig").Config;
const AliasTable = @import("alias_index.zig").AliasTable;
const Storage = @import("storage.zig").Storage;
const TenantCatalog = @import("tenant_index.zig").TenantCatalog;
const TenantIndex = @import("tenant_index.zig");
const TlsServer = @import("tls.zig").TlsServer;

pub const Server = struct {
    allocator: std.mem.Allocator,
    config: Config,
    storage: Storage,

    pub fn init(allocator: std.mem.Allocator, config: Config) Server {
        return .{
            .allocator = allocator,
            .config = config,
            .storage = Storage.init(config.data_dir),
        };
    }

    pub fn listen(self: *Server, io: Io) !std.Io.net.Server {
        const ip = try std.Io.net.IpAddress.parse(self.config.listen_address, self.config.listen_port);
        const listener = try ip.listen(io, .{ .reuse_address = true });
        std.debug.print("smtp listening on {any}\n", .{ip});
        return listener;
    }

    pub fn serve(
        self: *Server,
        io: Io,
        listener: *std.Io.net.Server,
        tenant_catalog: *const TenantCatalog,
        shutdown: *const std.atomic.Value(bool),
        tls_server: ?*TlsServer,
    ) !void {
        while (!shutdown.load(.acquire)) {
            const stream = listener.accept(io) catch |err| switch (err) {
                error.SocketNotListening, error.Canceled => return,
                else => {
                    std.debug.print("smtp accept error: {}\n", .{err});
                    continue;
                },
            };
            defer stream.close(io);
            self.serveConnection(io, stream, tenant_catalog, tls_server) catch |err| {
                std.debug.print("smtp session error: {}\n", .{err});
            };
        }
    }

    fn serveConnection(self: *Server, io: Io, stream: std.Io.net.Stream, tenant_catalog: *const TenantCatalog, tls_server: ?*TlsServer) !void {
        var read_buf: [1024]u8 = undefined;
        if (tls_server) |server| {
            var conn = try server.accept(stream.socket.handle, &read_buf, &.{});
            defer conn.deinit();
            return self.handleClient(io, &conn.reader, &conn.writer, tenant_catalog);
        }
        var reader = stream.reader(io, &read_buf);
        var writer = stream.writer(io, &.{});
        return self.handleClient(io, &reader.interface, &writer.interface, tenant_catalog);
    }

    fn handleClient(self: *Server, fs_io: Io, r: *Io.Reader, w: *Io.Writer, tenant_catalog: *const TenantCatalog) !void {
        try w.writeAll("220 ");
        try w.writeAll(self.config.hostname);
        try w.writeAll(" ESMTP raven ready\r\n");

        var sender: ?[]u8 = null;
        defer if (sender) |value| self.allocator.free(value);

        var auth_identity: ?MailIdentity = null;
        defer if (auth_identity) |value| freeMailIdentity(self.allocator, value);

        var auth_pending: ?AuthChallenge = null;

        var recipients = std.ArrayList(Recipient).empty;
        defer recipients.deinit(self.allocator);

        while (true) {
            const line = try nextLine(r) orelse return;

            if (auth_pending != null) {
                auth_pending = null;
                const identity = completeAuthPlain(self.allocator, fs_io, self.storage, tenant_catalog, line) catch {
                    try w.writeAll("535 5.7.8 Authentication failed\r\n");
                    continue;
                };

                if (auth_identity) |value| freeMailIdentity(self.allocator, value);
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

                    if (auth_identity) |value| freeMailIdentity(self.allocator, value);
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
                if (sender) |value| self.allocator.free(value);
                const request = parseRecipient(trimAfterColon(line)) catch {
                    try w.writeAll("501 bad sender\r\n");
                    continue;
                };

                const resolved_tenant = tenant_catalog.resolveTenant(request.tenant_hint, request.domain) catch {
                    try w.writeAll("550 sender not hosted\r\n");
                    continue;
                };

                if (auth_identity) |identity| {
                    if (!senderMatchesAuth(identity, resolved_tenant, request)) {
                        try w.writeAll("553 sender not authorized\r\n");
                        continue;
                    }
                } else if (!std.mem.eql(u8, resolved_tenant, request.domain)) {
                    try w.writeAll("530 authentication required\r\n");
                    continue;
                }

                sender = try self.allocator.dupe(u8, trimAfterColon(line));
                clearRecipients(self.allocator, &recipients);
                try w.writeAll("250 ok\r\n");
                continue;
            }

            if (startsWithIgnoreCase(line, "RCPT TO:")) {
                if (sender == null) {
                    try w.writeAll("503 need mail first\r\n");
                    continue;
                }

                const request = parseRecipient(trimAfterColon(line)) catch {
                    try w.writeAll("501 bad recipient\r\n");
                    continue;
                };

                const recipient = resolveRecipient(self.allocator, fs_io, self.storage, tenant_catalog, request) catch |err| switch (err) {
                    error.UnknownTenant, error.DomainNotHosted => {
                        try w.writeAll("550 mailbox unavailable\r\n");
                        continue;
                    },
                    else => return err,
                };

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

                const stored_path = try self.storage.writeInboundMessage(fs_io, self.allocator, message);
                defer self.allocator.free(stored_path);

                for (recipients.items) |recipient| {
                    const mailbox_path = try self.storage.deliverMailboxMessage(
                        fs_io,
                        self.allocator,
                        recipient.tenant,
                        recipient.domain,
                        recipient.user,
                        message,
                    );
                    defer self.allocator.free(mailbox_path);

                    std.debug.print("delivered to {s}@{s} at {s}\n", .{ recipient.user, recipient.domain, mailbox_path });
                }

                if (sender) |value| self.allocator.free(value);
                sender = null;
                clearRecipients(self.allocator, &recipients);
                std.debug.print("stored inbound message at {s}\n", .{stored_path});
                try w.writeAll("250 queued\r\n");
                continue;
            }

            try w.writeAll("502 command not implemented\r\n");
        }
    }
};

const Recipient = struct {
    tenant: []u8,
    domain: []u8,
    user: []u8,
};

const RecipientRequest = struct {
    tenant_hint: ?[]const u8,
    domain: []const u8,
    user: []const u8,
};

const AuthChallenge = enum { plain };

const AuthCommand = struct {
    mechanism: []const u8,
    initial_response: ?[]const u8,
};

const MailIdentity = struct {
    tenant: []u8,
    domain: []u8,
    user: []u8,
};

fn parseAuthCommand(line: []const u8) !AuthCommand {
    const after_auth = std.mem.trim(u8, line[4..], " \t");
    var parts = std.mem.tokenizeAny(u8, after_auth, " \t");
    const mechanism = parts.next() orelse return error.InvalidRecipient;
    return .{ .mechanism = mechanism, .initial_response = parts.next() };
}

fn completeAuthPlain(
    allocator: std.mem.Allocator,
    io: Io,
    storage: Storage,
    catalog: *const TenantCatalog,
    encoded: []const u8,
) !MailIdentity {
    const decoded = try decodeBase64Payload(allocator, std.mem.trim(u8, encoded, " \t"));
    defer allocator.free(decoded);

    const first_zero = std.mem.indexOfScalar(u8, decoded, 0) orelse return error.InvalidRecipient;
    const second_zero = std.mem.indexOfScalarPos(u8, decoded, first_zero + 1, 0) orelse return error.InvalidRecipient;

    const login = std.mem.trim(u8, decoded[first_zero + 1 .. second_zero], " \t");
    const password = decoded[second_zero + 1 ..];
    if (login.len == 0 or password.len == 0) return error.InvalidRecipient;

    const login_request = parseRecipient(login) catch return error.InvalidRecipient;
    const tenant_name = try catalog.resolveTenant(login_request.tenant_hint, login_request.domain);

    var account_store = try AccountStore.load(allocator, io, storage, tenant_name, login_request.domain);
    defer account_store.deinit(allocator);

    if (!account_store.verify(login_request.user, password)) return error.InvalidRecipient;

    return .{
        .tenant = try allocator.dupe(u8, tenant_name),
        .domain = try allocator.dupe(u8, login_request.domain),
        .user = try allocator.dupe(u8, login_request.user),
    };
}

fn decodeBase64Payload(allocator: std.mem.Allocator, encoded: []const u8) ![]u8 {
    const clean = std.mem.trim(u8, encoded, " \t");
    const codecs = [_]std.base64.Codecs{ std.base64.standard, std.base64.standard_no_pad };

    for (codecs) |codec| {
        const decoder = &codec.Decoder;
        const size = decoder.calcSizeForSlice(clean) catch continue;
        const buf = try allocator.alloc(u8, size);
        errdefer allocator.free(buf);

        decoder.decode(buf, clean) catch {
            allocator.free(buf);
            continue;
        };
        return buf;
    }

    return error.InvalidRecipient;
}

fn senderMatchesAuth(identity: MailIdentity, resolved_tenant: []const u8, request: RecipientRequest) bool {
    return std.mem.eql(u8, identity.tenant, resolved_tenant) and
        std.mem.eql(u8, identity.domain, request.domain) and
        std.mem.eql(u8, identity.user, request.user);
}

fn freeMailIdentity(allocator: std.mem.Allocator, identity: MailIdentity) void {
    allocator.free(identity.tenant);
    allocator.free(identity.domain);
    allocator.free(identity.user);
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

fn parseRecipient(raw: []const u8) !RecipientRequest {
    const addr = address.parse(raw) catch return error.InvalidRecipient;
    return .{ .tenant_hint = addr.tag, .domain = addr.domain, .user = addr.user };
}

fn resolveRecipient(
    allocator: std.mem.Allocator,
    io: Io,
    storage: Storage,
    catalog: *const TenantCatalog,
    request: RecipientRequest,
) !Recipient {
    const tenant_name = try catalog.resolveTenant(request.tenant_hint, request.domain);
    const tenant = try allocator.dupe(u8, tenant_name);
    errdefer allocator.free(tenant);

    const domain = try allocator.dupe(u8, request.domain);
    errdefer allocator.free(domain);

    var alias_table = try AliasTable.load(allocator, io, storage, tenant_name, request.domain);
    defer alias_table.deinit(allocator);

    const target_user = alias_table.resolve(request.user);

    const user = try allocator.dupe(u8, target_user);
    errdefer allocator.free(user);

    return .{ .tenant = tenant, .domain = domain, .user = user };
}

fn clearRecipients(allocator: std.mem.Allocator, recipients: *std.ArrayList(Recipient)) void {
    for (recipients.items) |recipient| {
        allocator.free(recipient.tenant);
        allocator.free(recipient.domain);
        allocator.free(recipient.user);
    }
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

test "parseRecipient defaults tenant to domain" {
    const request = try parseRecipient("<alice@example.com>");

    try std.testing.expectEqualStrings("example.com", request.domain);
    try std.testing.expectEqualStrings("alice", request.user);
    try std.testing.expect(request.tenant_hint == null);
}

test "parseRecipient supports tenant suffix" {
    const request = try parseRecipient("alice+acme@example.com");

    try std.testing.expectEqualStrings("acme", request.tenant_hint.?);
    try std.testing.expectEqualStrings("example.com", request.domain);
    try std.testing.expectEqualStrings("alice", request.user);
}

test "resolveRecipient uses manifest tenant mapping" {
    const allocator = std.testing.allocator;
    const raw =
        \\tenant acme example.com
        \\tenant beta beta.com
    ;

    var catalog = try TenantIndex.parseForTest(allocator, raw);
    defer catalog.deinit(allocator);

    const request = try parseRecipient("alice@example.com");
    const recipient = try resolveRecipient(allocator, std.testing.io, Storage.init("data"), &catalog, request);
    defer allocator.free(recipient.tenant);
    defer allocator.free(recipient.domain);
    defer allocator.free(recipient.user);

    try std.testing.expectEqualStrings("acme", recipient.tenant);
}

test "resolveRecipient applies domain alias" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.createDirPath(std.testing.io, "tenants/acme/domains/example.com");
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "tenants/index.txt",
        .data =
        \\tenant acme example.com
        ,
    });
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "tenants/acme/domains/example.com/aliases.txt",
        .data =
        \\sales team-sales
        ,
    });

    const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", tmp.sub_path[0..] });
    defer allocator.free(root);

    var catalog = try TenantIndex.parseForTest(allocator, "tenant acme example.com\n");
    defer catalog.deinit(allocator);

    const request = try parseRecipient("sales@example.com");
    const recipient = try resolveRecipient(allocator, std.testing.io, Storage.init(root), &catalog, request);
    defer allocator.free(recipient.tenant);
    defer allocator.free(recipient.domain);
    defer allocator.free(recipient.user);

    try std.testing.expectEqualStrings("team-sales", recipient.user);
}

test "completeAuthPlain authenticates hosted account" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var catalog = try TenantIndex.parseForTest(allocator, "tenant acme example.com\n");
    defer catalog.deinit(allocator);

    var hash_buf: [64]u8 = undefined;
    const hash = @import("account_index.zig").passwordHashHex("secret", &hash_buf);
    const accounts = try std.fmt.allocPrint(allocator, "alice {s}\n", .{hash});
    defer allocator.free(accounts);

    try tmp.dir.createDirPath(std.testing.io, "tenants/acme/domains/example.com");
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "tenants/acme/domains/example.com/accounts.txt",
        .data = accounts,
    });

    const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", tmp.sub_path[0..] });
    defer allocator.free(root);

    const payload = try buildPlainAuthPayload(allocator, "alice@example.com", "secret");
    defer allocator.free(payload);

    const identity = try completeAuthPlain(allocator, std.testing.io, Storage.init(root), &catalog, payload);
    defer freeMailIdentity(allocator, identity);

    try std.testing.expectEqualStrings("acme", identity.tenant);
    try std.testing.expectEqualStrings("example.com", identity.domain);
    try std.testing.expectEqualStrings("alice", identity.user);
}

test "completeAuthPlain rejects bad password" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var catalog = try TenantIndex.parseForTest(allocator, "tenant acme example.com\n");
    defer catalog.deinit(allocator);

    var hash_buf: [64]u8 = undefined;
    const hash = @import("account_index.zig").passwordHashHex("secret", &hash_buf);
    const accounts = try std.fmt.allocPrint(allocator, "alice {s}\n", .{hash});
    defer allocator.free(accounts);

    try tmp.dir.createDirPath(std.testing.io, "tenants/acme/domains/example.com");
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "tenants/acme/domains/example.com/accounts.txt",
        .data = accounts,
    });

    const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", tmp.sub_path[0..] });
    defer allocator.free(root);

    const payload = try buildPlainAuthPayload(allocator, "alice@example.com", "wrong");
    defer allocator.free(payload);

    try std.testing.expectError(error.InvalidRecipient, completeAuthPlain(allocator, std.testing.io, Storage.init(root), &catalog, payload));
}

test "senderMatchesAuth enforces exact sender" {
    const allocator = std.testing.allocator;
    const identity = MailIdentity{
        .tenant = try allocator.dupe(u8, "acme"),
        .domain = try allocator.dupe(u8, "example.com"),
        .user = try allocator.dupe(u8, "alice"),
    };
    defer freeMailIdentity(allocator, identity);

    const request = try parseRecipient("alice@example.com");
    try std.testing.expect(senderMatchesAuth(identity, "acme", request));
    try std.testing.expect(!senderMatchesAuth(identity, "beta", request));
}

fn buildPlainAuthPayload(allocator: std.mem.Allocator, login: []const u8, password: []const u8) ![]u8 {
    const raw_len = login.len + password.len + 2;
    var raw = try allocator.alloc(u8, raw_len);
    errdefer allocator.free(raw);

    raw[0] = 0;
    @memcpy(raw[1 .. 1 + login.len], login);
    raw[1 + login.len] = 0;
    @memcpy(raw[2 + login.len ..], password);

    const encoded_len = std.base64.standard.Encoder.calcSize(raw.len);
    const encoded = try allocator.alloc(u8, encoded_len);
    errdefer allocator.free(encoded);

    _ = std.base64.standard.Encoder.encode(encoded, raw);
    allocator.free(raw);
    return encoded;
}

test "smtp session delivers a pipelined transaction" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", tmp.sub_path[0..] });
    defer allocator.free(root);

    var catalog = try TenantIndex.parseForTest(allocator, "tenant acme example.com\n");
    defer catalog.deinit(allocator);

    var server = Server.init(allocator, .{ .data_dir = root });
    var in: Io.Reader = .fixed("EHLO client\r\nMAIL FROM:<bob@external.test>\r\nRCPT TO:<alice@example.com>\r\n" ++
        "DATA\r\nSubject: hi\r\n\r\n..dot\r\n.\r\nQUIT\r\n");
    var out: Io.Writer.Allocating = .init(allocator);
    defer out.deinit();

    try server.handleClient(std.testing.io, &in, &out.writer, &catalog);

    try std.testing.expectEqualStrings("220 localhost ESMTP raven ready\r\n" ++
        "250-localhost\r\n250-AUTH PLAIN\r\n250 PIPELINING\r\n" ++
        "250 ok\r\n250 ok\r\n354 end with <CR><LF>.<CR><LF>\r\n250 queued\r\n221 bye\r\n", out.written());

    const messages = try server.storage.listMailboxMessages(std.testing.io, allocator, "acme", "example.com", "alice");
    defer @import("storage.zig").freeMailboxMessages(allocator, messages);
    try std.testing.expectEqual(@as(usize, 1), messages.len);
    const body = try server.storage.readMailboxMessage(std.testing.io, allocator, "acme", "example.com", "alice", messages[0].name);
    defer allocator.free(body);
    try std.testing.expectEqualStrings("Subject: hi\r\n\r\n.dot\r\n", body);
}

test "smtp session rejects path traversal in addresses" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", tmp.sub_path[0..], "data" });
    defer allocator.free(root);

    var catalog = try TenantIndex.parseForTest(allocator, "tenant acme example.com\n");
    defer catalog.deinit(allocator);

    var server = Server.init(allocator, .{ .data_dir = root });
    var in: Io.Reader = .fixed("MAIL FROM:<../../x@external.test>\r\nMAIL FROM:<bob@external.test>\r\n" ++
        "RCPT TO:<../../../../../escape@example.com>\r\nRCPT TO:<alice@../../../escape>\r\nDATA\r\nQUIT\r\n");
    var out: Io.Writer.Allocating = .init(allocator);
    defer out.deinit();

    try server.handleClient(std.testing.io, &in, &out.writer, &catalog);

    try std.testing.expectEqualStrings("220 localhost ESMTP raven ready\r\n501 bad sender\r\n250 ok\r\n" ++
        "501 bad recipient\r\n501 bad recipient\r\n503 need rcpt first\r\n221 bye\r\n", out.written());
    try std.testing.expectError(error.FileNotFound, tmp.dir.access(std.testing.io, "escape", .{}));
    try std.testing.expectError(error.FileNotFound, tmp.dir.access(std.testing.io, "data", .{}));
}

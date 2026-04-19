const std = @import("std");

const Io = std.Io;
const Config = @import("config.zig").Config;
const AccountStore = @import("account_index.zig").AccountStore;
const Storage = @import("storage.zig").Storage;
const freeMailboxMessages = @import("storage.zig").freeMailboxMessages;
const TenantCatalog = @import("tenant_index.zig").TenantCatalog;

pub const ImapServer = struct {
    allocator: std.mem.Allocator,
    config: Config,
    storage: Storage,
    tenant_catalog: *const TenantCatalog,

    pub fn init(
        allocator: std.mem.Allocator,
        config: Config,
        storage: Storage,
        tenant_catalog: *const TenantCatalog,
    ) ImapServer {
        return .{
            .allocator = allocator,
            .config = config,
            .storage = storage,
            .tenant_catalog = tenant_catalog,
        };
    }

    pub fn run(self: *ImapServer) !void {
        const io = std.Options.debug_io;
        var listener = try self.listen(io);
        defer listener.deinit(io);

        var shutdown = std.atomic.Value(bool).init(false);
        try self.serve(io, &listener, &shutdown);
    }

    pub fn listen(self: *ImapServer, io: Io) !std.Io.net.Server {
        const address = try std.Io.net.IpAddress.parse(self.config.listen_address, self.config.imap_port);
        const listener = try address.listen(io, .{ .reuse_address = true });
        std.debug.print("imap listening on {any}\n", .{address});
        return listener;
    }

    pub fn serve(self: *ImapServer, io: Io, listener: *std.Io.net.Server, shutdown: *const std.atomic.Value(bool)) !void {
        while (!shutdown.load(.seq_cst)) {
            var stream = listener.accept(io) catch |err| switch (err) {
                error.SocketNotListening => return,
                else => {
                    std.debug.print("imap accept error: {}\n", .{err});
                    continue;
                },
            };
            defer stream.close(io);

            self.handleClient(io, stream) catch |err| {
                std.debug.print("imap session error: {}\n", .{err});
            };
        }
    }

    fn handleClient(self: *ImapServer, io: Io, stream: std.Io.net.Stream) !void {
        var read_buf: [1024]u8 = undefined;
        var write_buf: [1024]u8 = undefined;
        var reader = stream.reader(io, &read_buf);
        var writer = stream.writer(io, &write_buf);
        const r = &reader.interface;
        const w = &writer.interface;

        try w.writeAll("* OK IMAP4rev1 raven ready\r\n");

        var session = Session{};
        defer session.deinit(self.allocator);

        while (true) {
            const line = try nextLine(r) orelse return;

            var parts = std.mem.tokenizeAny(u8, line, " \t");
            const tag = parts.next() orelse continue;
            const command = parts.next() orelse {
                try taggedBad(w, tag, "missing command");
                continue;
            };

            if (std.ascii.eqlIgnoreCase(command, "NOOP")) {
                try taggedOk(w, tag, "NOOP completed");
                continue;
            }

            if (std.ascii.eqlIgnoreCase(command, "LOGOUT")) {
                try w.writeAll("* BYE raven logging out\r\n");
                try taggedOk(w, tag, "LOGOUT completed");
                return;
            }

            if (std.ascii.eqlIgnoreCase(command, "CAPABILITY")) {
                try w.writeAll("* CAPABILITY IMAP4rev1 LITERAL+\r\n");
                try taggedOk(w, tag, "CAPABILITY completed");
                continue;
            }

            if (std.ascii.eqlIgnoreCase(command, "LOGIN")) {
                const login_arg = parts.next() orelse {
                    try taggedBad(w, tag, "missing login address");
                    continue;
                };

                const password = parts.next() orelse {
                    try taggedBad(w, tag, "missing password");
                    continue;
                };

                const identity = resolveLoginIdentity(self.allocator, self.tenant_catalog, login_arg) catch |err| switch (err) {
                    error.InvalidLogin => {
                        try taggedBad(w, tag, "invalid login");
                        continue;
                    },
                    else => return err,
                };

                var account_store = try AccountStore.load(self.allocator, io, self.storage, identity.tenant, identity.domain);
                defer account_store.deinit(self.allocator);

                if (!account_store.verify(identity.user, password)) {
                    freeLoginIdentity(self.allocator, identity);
                    try taggedNo(w, tag, "auth failed");
                    continue;
                }

                try session.setIdentity(self.allocator, identity);
                try taggedOk(w, tag, "LOGIN completed");
                continue;
            }

            if (std.ascii.eqlIgnoreCase(command, "LIST")) {
                if (!session.isAuthenticated()) {
                    try taggedNo(w, tag, "login first");
                    continue;
                }

                try w.writeAll("* LIST (\\HasNoChildren) \"/\" \"INBOX\"\r\n");
                try taggedOk(w, tag, "LIST completed");
                continue;
            }

            if (std.ascii.eqlIgnoreCase(command, "SELECT") or std.ascii.eqlIgnoreCase(command, "EXAMINE")) {
                if (!session.isAuthenticated()) {
                    try taggedNo(w, tag, "login first");
                    continue;
                }

                const mailbox = parts.next() orelse {
                    try taggedBad(w, tag, "missing mailbox");
                    continue;
                };

                if (!std.ascii.eqlIgnoreCase(mailbox, "INBOX")) {
                    try taggedNo(w, tag, "only INBOX is supported");
                    continue;
                }

                try session.loadMailbox(self.allocator, io, self.storage);
                const flags_line = try session.supportedFlags(self.allocator);
                defer self.allocator.free(flags_line);

                try w.writeAll("* FLAGS ");
                try w.writeAll(flags_line);
                try w.writeAll("\r\n");
                try w.print("* {d} EXISTS\r\n", .{session.messages.len});
                try w.writeAll("* 0 RECENT\r\n");
                try w.writeAll("* OK [UIDVALIDITY 1] stable\r\n");
                try taggedOk(w, tag, if (std.ascii.eqlIgnoreCase(command, "EXAMINE")) "READ-ONLY selected" else "READ-WRITE selected");
                continue;
            }

            if (std.ascii.eqlIgnoreCase(command, "FETCH")) {
                if (!session.isAuthenticated()) {
                    try taggedNo(w, tag, "login first");
                    continue;
                }

                if (session.messages.len == 0) {
                    try taggedNo(w, tag, "select mailbox first");
                    continue;
                }

                const number_text = parts.next() orelse {
                    try taggedBad(w, tag, "missing message number");
                    continue;
                };

                const number = std.fmt.parseInt(usize, number_text, 10) catch {
                    try taggedBad(w, tag, "bad message number");
                    continue;
                };

                if (number == 0 or number > session.messages.len) {
                    try taggedNo(w, tag, "no such message");
                    continue;
                }

                const message = session.messages[number - 1];
                const flags_text = try message.flags.format(self.allocator);
                defer self.allocator.free(flags_text);

                const data = try self.storage.readMailboxMessage(
                    io,
                    self.allocator,
                    session.tenant.?,
                    session.domain.?,
                    session.user.?,
                    message.name,
                );
                defer self.allocator.free(data);

                try w.print("* {d} FETCH (FLAGS {s} BODY[] {d}\r\n", .{ number, flags_text, data.len });
                try w.writeAll(data);
                try w.writeAll("\r\n)\r\n");
                try taggedOk(w, tag, "FETCH completed");
                continue;
            }

            if (std.ascii.eqlIgnoreCase(command, "STORE")) {
                if (!session.isAuthenticated()) {
                    try taggedNo(w, tag, "login first");
                    continue;
                }

                if (session.messages.len == 0) {
                    try taggedNo(w, tag, "select mailbox first");
                    continue;
                }

                const number_text = parts.next() orelse {
                    try taggedBad(w, tag, "missing message number");
                    continue;
                };
                const op = parts.next() orelse {
                    try taggedBad(w, tag, "missing store op");
                    continue;
                };
                const flags_text = parts.next() orelse {
                    try taggedBad(w, tag, "missing flags");
                    continue;
                };

                if (!std.mem.startsWith(u8, op, "+FLAGS")) {
                    try taggedNo(w, tag, "only +FLAGS supported");
                    continue;
                }

                const number = std.fmt.parseInt(usize, number_text, 10) catch {
                    try taggedBad(w, tag, "bad message number");
                    continue;
                };

                if (number == 0 or number > session.messages.len) {
                    try taggedNo(w, tag, "no such message");
                    continue;
                }

                const added = parseFlagsList(flags_text);
                var message = &session.messages[number - 1];
                message.flags = message.flags.merge(added);

                try self.storage.writeMailboxFlags(
                    io,
                    self.allocator,
                    session.tenant.?,
                    session.domain.?,
                    session.user.?,
                    message.name,
                    message.flags,
                );

                try taggedOk(w, tag, "STORE completed");
                continue;
            }

            if (std.ascii.eqlIgnoreCase(command, "EXPUNGE")) {
                if (!session.isAuthenticated()) {
                    try taggedNo(w, tag, "login first");
                    continue;
                }

                if (session.messages.len == 0) {
                    try taggedOk(w, tag, "EXPUNGE completed");
                    continue;
                }

                var i: usize = session.messages.len;
                while (i > 0) : (i -= 1) {
                    const idx = i - 1;
                    if (!session.messages[idx].flags.deleted) continue;

                    try self.storage.deleteMailboxMessage(
                        io,
                        self.allocator,
                        session.tenant.?,
                        session.domain.?,
                        session.user.?,
                        session.messages[idx].name,
                    );

                    try w.print("* {d} EXPUNGE\r\n", .{idx + 1});
                    session.removeMessage(idx, self.allocator);
                }
                try taggedOk(w, tag, "EXPUNGE completed");
                continue;
            }

            try taggedBad(w, tag, "unknown command");
        }
    }
};

const Session = struct {
    tenant: ?[]u8 = null,
    domain: ?[]u8 = null,
    user: ?[]u8 = null,
    messages: []Storage.MailboxMessage = &.{},

    fn isAuthenticated(self: Session) bool {
        return self.tenant != null and self.domain != null and self.user != null;
    }

    fn setIdentity(self: *Session, allocator: std.mem.Allocator, identity: LoginIdentity) !void {
        self.clearSelected(allocator);
        self.clearIdentity(allocator);
        self.tenant = identity.tenant;
        self.domain = identity.domain;
        self.user = identity.user;
    }

    fn loadMailbox(self: *Session, allocator: std.mem.Allocator, io: Io, storage: Storage) !void {
        self.clearSelected(allocator);
        self.messages = try storage.listMailboxMessages(io, allocator, self.tenant.?, self.domain.?, self.user.?);
    }

    fn supportedFlags(self: Session, allocator: std.mem.Allocator) ![]u8 {
        _ = self;
        const flags = Storage.MessageFlags{};
        return flags.format(allocator);
    }

    fn clearSelected(self: *Session, allocator: std.mem.Allocator) void {
        if (self.messages.len > 0) freeMailboxMessages(allocator, self.messages);
        self.messages = &.{};
    }

    fn removeMessage(self: *Session, index: usize, allocator: std.mem.Allocator) void {
        allocator.free(self.messages[index].name);
        allocator.free(self.messages[index].path);

        if (index + 1 < self.messages.len) {
            std.mem.copyForwards(Storage.MailboxMessage, self.messages[index..], self.messages[index + 1 ..]);
        }

        self.messages.len -= 1;
    }

    fn clearIdentity(self: *Session, allocator: std.mem.Allocator) void {
        if (self.tenant) |value| allocator.free(value);
        if (self.domain) |value| allocator.free(value);
        if (self.user) |value| allocator.free(value);
        self.tenant = null;
        self.domain = null;
        self.user = null;
    }

    fn deinit(self: *Session, allocator: std.mem.Allocator) void {
        self.clearSelected(allocator);
        self.clearIdentity(allocator);
        self.* = .{};
    }
};

const LoginIdentity = struct {
    tenant: []u8,
    domain: []u8,
    user: []u8,
};

fn resolveLoginIdentity(allocator: std.mem.Allocator, catalog: *const TenantCatalog, raw: []const u8) !LoginIdentity {
    const address = extractAddress(raw);
    const at_index = std.mem.indexOfScalar(u8, address, '@') orelse return error.InvalidLogin;

    const local_part = std.mem.trim(u8, address[0..at_index], " <>\"");
    const domain_text = std.mem.trim(u8, address[at_index + 1 ..], " <>\"");
    if (local_part.len == 0 or domain_text.len == 0) return error.InvalidLogin;

    const split = splitTenantSuffix(local_part);
    const tenant_name = try catalog.resolveTenant(split.tenant, domain_text);

    return .{
        .tenant = try allocator.dupe(u8, tenant_name),
        .domain = try allocator.dupe(u8, domain_text),
        .user = try allocator.dupe(u8, split.user),
    };
}

fn freeLoginIdentity(allocator: std.mem.Allocator, identity: LoginIdentity) void {
    allocator.free(identity.tenant);
    allocator.free(identity.domain);
    allocator.free(identity.user);
}

fn splitTenantSuffix(local_part: []const u8) struct { user: []const u8, tenant: ?[]const u8 } {
    if (std.mem.lastIndexOfScalar(u8, local_part, '+')) |plus_index| {
        if (plus_index > 0 and plus_index + 1 < local_part.len) {
            return .{ .user = local_part[0..plus_index], .tenant = local_part[plus_index + 1 ..] };
        }
    }
    return .{ .user = local_part, .tenant = null };
}

fn extractAddress(raw: []const u8) []const u8 {
    if (std.mem.indexOfScalar(u8, raw, '<')) |open| {
        if (std.mem.lastIndexOfScalar(u8, raw, '>')) |close| {
            if (close > open + 1) return raw[open + 1 .. close];
        }
    }
    return raw;
}

fn parseFlagsList(raw: []const u8) Storage.MessageFlags {
    var flags = Storage.MessageFlags{};
    const trimmed = std.mem.trim(u8, raw, " \t");
    const inner = if (trimmed.len >= 2 and trimmed[0] == '(' and trimmed[trimmed.len - 1] == ')') trimmed[1 .. trimmed.len - 1] else trimmed;

    var parts = std.mem.tokenizeAny(u8, inner, " \t");
    while (parts.next()) |part| {
        if (std.mem.eql(u8, part, "\\Seen")) flags.seen = true else
        if (std.mem.eql(u8, part, "\\Answered")) flags.answered = true else
        if (std.mem.eql(u8, part, "\\Flagged")) flags.flagged = true else
        if (std.mem.eql(u8, part, "\\Deleted")) flags.deleted = true else
        if (std.mem.eql(u8, part, "\\Draft")) flags.draft = true else {}
    }

    return flags;
}

fn nextLine(reader: *Io.Reader) !?[]const u8 {
    const line = reader.takeDelimiterExclusive('\n') catch |err| switch (err) {
        error.EndOfStream => return null,
        else => return err,
    };
    return trimCr(line);
}

fn trimCr(line: []const u8) []const u8 {
    if (line.len > 0 and line[line.len - 1] == '\r') return line[0 .. line.len - 1];
    return line;
}

fn taggedOk(w: *Io.Writer, tag: []const u8, msg: []const u8) !void {
    try w.writeAll(tag);
    try w.writeAll(" OK ");
    try w.writeAll(msg);
    try w.writeAll("\r\n");
}

fn taggedNo(w: *Io.Writer, tag: []const u8, msg: []const u8) !void {
    try w.writeAll(tag);
    try w.writeAll(" NO ");
    try w.writeAll(msg);
    try w.writeAll("\r\n");
}

fn taggedBad(w: *Io.Writer, tag: []const u8, msg: []const u8) !void {
    try w.writeAll(tag);
    try w.writeAll(" BAD ");
    try w.writeAll(msg);
    try w.writeAll("\r\n");
}

test "resolveLoginIdentity defaults tenant to domain" {
    const allocator = std.testing.allocator;
    var catalog = try @import("tenant_index.zig").parseForTest(allocator, "tenant acme example.com\n");
    defer catalog.deinit(allocator);

    const identity = try resolveLoginIdentity(allocator, &catalog, "alice@example.com");
    defer allocator.free(identity.tenant);
    defer allocator.free(identity.domain);
    defer allocator.free(identity.user);

    try std.testing.expectEqualStrings("acme", identity.tenant);
    try std.testing.expectEqualStrings("example.com", identity.domain);
    try std.testing.expectEqualStrings("alice", identity.user);
}

test "resolveLoginIdentity supports tenant suffix" {
    const allocator = std.testing.allocator;
    var catalog = try @import("tenant_index.zig").parseForTest(allocator, "tenant acme example.com\n");
    defer catalog.deinit(allocator);

    const identity = try resolveLoginIdentity(allocator, &catalog, "alice+acme@example.com");
    defer allocator.free(identity.tenant);
    defer allocator.free(identity.domain);
    defer allocator.free(identity.user);

    try std.testing.expectEqualStrings("acme", identity.tenant);
    try std.testing.expectEqualStrings("example.com", identity.domain);
    try std.testing.expectEqualStrings("alice", identity.user);
}

test "login identity helper frees cleanly" {
    const allocator = std.testing.allocator;
    const identity = LoginIdentity{
        .tenant = try allocator.dupe(u8, "acme"),
        .domain = try allocator.dupe(u8, "example.com"),
        .user = try allocator.dupe(u8, "alice"),
    };
    freeLoginIdentity(allocator, identity);
}

test "parseFlagsList reads standard flags" {
    const flags = parseFlagsList("(\\Seen \\Flagged)");
    try std.testing.expect(flags.seen);
    try std.testing.expect(flags.flagged);
    try std.testing.expect(!flags.deleted);
}

test "session removeMessage compacts mailbox" {
    const allocator = std.testing.allocator;
    var session = Session{};
    session.messages = try allocator.alloc(Storage.MailboxMessage, 3);
    session.messages[0] = .{ .name = try allocator.dupe(u8, "1.eml"), .path = try allocator.dupe(u8, "p1"), .size = 1, .sequence = 1, .flags = .{} };
    session.messages[1] = .{ .name = try allocator.dupe(u8, "2.eml"), .path = try allocator.dupe(u8, "p2"), .size = 1, .sequence = 2, .flags = .{ .deleted = true } };
    session.messages[2] = .{ .name = try allocator.dupe(u8, "3.eml"), .path = try allocator.dupe(u8, "p3"), .size = 1, .sequence = 3, .flags = .{} };

    session.removeMessage(1, allocator);

    try std.testing.expectEqual(@as(usize, 2), session.messages.len);
    try std.testing.expectEqualStrings("1.eml", session.messages[0].name);
    try std.testing.expectEqualStrings("3.eml", session.messages[1].name);

    session.clearSelected(allocator);
}

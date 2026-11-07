const std = @import("std");

const Io = std.Io;
const Config = @import("config.zig").Config;
const account_index = @import("account_index.zig");
const Identity = account_index.Identity;
const Storage = @import("storage.zig").Storage;
const Message = @import("storage.zig").Message;
const MessageFlags = @import("storage.zig").MessageFlags;
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

    pub fn listen(self: *ImapServer, io: Io) !std.Io.net.Server {
        const ip = try std.Io.net.IpAddress.parse(self.config.listen_address, self.config.imap_port);
        const listener = try ip.listen(io, .{ .reuse_address = true });
        std.debug.print("imap listening on {any}\n", .{ip});
        return listener;
    }

    pub fn handleClient(self: *ImapServer, fs_io: Io, r: *Io.Reader, w: *Io.Writer) !void {
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

                const identity = account_index.authenticate(self.allocator, fs_io, self.storage, self.tenant_catalog, login_arg, password) catch |err| switch (err) {
                    error.AuthFailed => {
                        try taggedNo(w, tag, "auth failed");
                        continue;
                    },
                    else => return err,
                };
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

                try session.loadMailbox(self.allocator, fs_io, self.storage);
                const flags_line = try session.supportedFlags(self.allocator);
                defer self.allocator.free(flags_line);

                try w.writeAll("* FLAGS ");
                try w.writeAll(flags_line);
                try w.writeAll("\r\n");
                try w.print("* {d} EXISTS\r\n", .{session.messages.items.len});
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

                if (session.messages.items.len == 0) {
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

                if (number == 0 or number > session.messages.items.len) {
                    try taggedNo(w, tag, "no such message");
                    continue;
                }

                const message = session.messages.items[number - 1];
                const flags_text = try message.flags.format(self.allocator);
                defer self.allocator.free(flags_text);

                const data = Storage.readMessage(fs_io, self.allocator, message) catch |err| switch (err) {
                    error.FileNotFound => {
                        try taggedNo(w, tag, "message no longer available");
                        continue;
                    },
                    else => return err,
                };
                defer self.allocator.free(data);

                try w.print("* {d} FETCH (FLAGS {s} BODY[] {{{d}}}\r\n", .{ number, flags_text, data.len });
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

                if (session.messages.items.len == 0) {
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

                if (number == 0 or number > session.messages.items.len) {
                    try taggedNo(w, tag, "no such message");
                    continue;
                }

                const message = &session.messages.items[number - 1];
                Storage.setFlags(fs_io, self.allocator, message, message.flags.merge(parseFlagsList(flags_text))) catch |err| switch (err) {
                    error.FileNotFound => {
                        try taggedNo(w, tag, "message no longer available");
                        continue;
                    },
                    else => return err,
                };

                try taggedOk(w, tag, "STORE completed");
                continue;
            }

            if (std.ascii.eqlIgnoreCase(command, "EXPUNGE")) {
                if (!session.isAuthenticated()) {
                    try taggedNo(w, tag, "login first");
                    continue;
                }

                if (session.messages.items.len == 0) {
                    try taggedOk(w, tag, "EXPUNGE completed");
                    continue;
                }

                var i: usize = session.messages.items.len;
                while (i > 0) : (i -= 1) {
                    const idx = i - 1;
                    if (!session.messages.items[idx].flags.deleted) continue;

                    try Storage.deleteMessage(fs_io, session.messages.items[idx]);

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
    messages: std.ArrayList(Message) = .empty,

    fn isAuthenticated(self: Session) bool {
        return self.tenant != null and self.domain != null and self.user != null;
    }

    fn setIdentity(self: *Session, allocator: std.mem.Allocator, identity: Identity) !void {
        self.clearSelected(allocator);
        self.clearIdentity(allocator);
        self.tenant = identity.tenant;
        self.domain = identity.domain;
        self.user = identity.user;
    }

    fn loadMailbox(self: *Session, allocator: std.mem.Allocator, fs_io: Io, storage: Storage) !void {
        self.clearSelected(allocator);
        self.messages = .fromOwnedSlice(try storage.listMailbox(fs_io, allocator, self.tenant.?, self.domain.?, self.user.?));
    }

    fn supportedFlags(self: Session, allocator: std.mem.Allocator) ![]u8 {
        _ = self;
        const flags = MessageFlags{};
        return flags.format(allocator);
    }

    fn clearSelected(self: *Session, allocator: std.mem.Allocator) void {
        for (self.messages.items) |message| allocator.free(message.path);
        self.messages.deinit(allocator);
        self.messages = .empty;
    }

    fn removeMessage(self: *Session, index: usize, allocator: std.mem.Allocator) void {
        allocator.free(self.messages.orderedRemove(index).path);
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

fn parseFlagsList(raw: []const u8) MessageFlags {
    var flags = MessageFlags{};
    const trimmed = std.mem.trim(u8, raw, " \t");
    const inner = if (trimmed.len >= 2 and trimmed[0] == '(' and trimmed[trimmed.len - 1] == ')') trimmed[1 .. trimmed.len - 1] else trimmed;

    var parts = std.mem.tokenizeAny(u8, inner, " \t");
    while (parts.next()) |part| {
        if (std.mem.eql(u8, part, "\\Seen")) flags.seen = true else if (std.mem.eql(u8, part, "\\Answered")) flags.answered = true else if (std.mem.eql(u8, part, "\\Flagged")) flags.flagged = true else if (std.mem.eql(u8, part, "\\Deleted")) flags.deleted = true else if (std.mem.eql(u8, part, "\\Draft")) flags.draft = true else {}
    }

    return flags;
}

fn nextLine(reader: *Io.Reader) !?[]const u8 {
    const line = try reader.takeDelimiter('\n') orelse return null;
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

test "parseFlagsList reads standard flags" {
    const flags = parseFlagsList("(\\Seen \\Flagged)");
    try std.testing.expect(flags.seen);
    try std.testing.expect(flags.flagged);
    try std.testing.expect(!flags.deleted);
}

test "session removeMessage compacts mailbox" {
    const allocator = std.testing.allocator;
    var session = Session{};
    try session.messages.append(allocator, .{ .path = try allocator.dupe(u8, "cur/1:2,"), .size = 1, .flags = .{} });
    try session.messages.append(allocator, .{ .path = try allocator.dupe(u8, "cur/2:2,T"), .size = 1, .flags = .{ .deleted = true } });
    try session.messages.append(allocator, .{ .path = try allocator.dupe(u8, "cur/3:2,"), .size = 1, .flags = .{} });

    session.removeMessage(1, allocator);

    try std.testing.expectEqual(@as(usize, 2), session.messages.items.len);
    try std.testing.expectEqualStrings("cur/1:2,", session.messages.items[0].path);
    try std.testing.expectEqualStrings("cur/3:2,", session.messages.items[1].path);

    session.clearSelected(allocator);
}

test "imap session logs in, selects and fetches" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", tmp.sub_path[0..] });
    defer allocator.free(root);

    var hash_buf: [64]u8 = undefined;
    const accounts = try std.fmt.allocPrint(allocator, "alice {s}\n", .{@import("account_index.zig").passwordHashHex("secret", &hash_buf)});
    defer allocator.free(accounts);
    try tmp.dir.createDirPath(std.testing.io, "tenants/acme/domains/example.com/users/alice/Maildir/new");
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "tenants/acme/domains/example.com/accounts.txt", .data = accounts });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "tenants/acme/domains/example.com/users/alice/Maildir/new/1.eml", .data = "Subject: hi\r\n\r\nhello\r\n" });

    var catalog = try @import("tenant_index.zig").parseForTest(allocator, "tenant acme example.com\n");
    defer catalog.deinit(allocator);

    var server = ImapServer.init(allocator, .{ .data_dir = root }, Storage.init(root), &catalog);
    var in: Io.Reader = .fixed("a1 LOGIN alice@example.com wrong\r\na2 LOGIN alice@example.com secret\r\n" ++
        "a3 SELECT INBOX\r\na4 FETCH 1 BODY[]\r\na5 LOGOUT\r\n");
    var out: Io.Writer.Allocating = .init(allocator);
    defer out.deinit();

    try server.handleClient(std.testing.io, &in, &out.writer);

    const transcript = out.written();
    for ([_][]const u8{
        "a1 NO auth failed\r\n",
        "a2 OK LOGIN completed\r\n",
        "* 1 EXISTS\r\n",
        "* 1 FETCH (FLAGS () BODY[] {22}\r\nSubject: hi\r\n\r\nhello\r\n\r\n)\r\na4 OK FETCH completed\r\n",
        "a5 OK LOGOUT completed\r\n",
    }) |expected| {
        if (std.mem.indexOf(u8, transcript, expected) == null) {
            std.debug.print("missing \"{s}\" in:\n{s}\n", .{ expected, transcript });
            return error.TestExpectedEqual;
        }
    }
}

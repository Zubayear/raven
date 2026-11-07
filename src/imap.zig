const std = @import("std");

const Io = std.Io;
const Config = @import("config.zig").Config;
const conn = @import("conn.zig");
const account_index = @import("account_index.zig");
const Identity = account_index.Identity;
const Storage = @import("storage.zig").Storage;
const Message = @import("storage.zig").Message;
const MessageFlags = @import("storage.zig").MessageFlags;
const TenantCatalog = @import("tenant_index.zig").TenantCatalog;
const proto = @import("imap_proto.zig");

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

    pub fn handleClient(self: *ImapServer, fs_io: Io, client: *conn.Client) !void {
        const w = client.writer;
        try w.writeAll("* OK [CAPABILITY " ++ capabilities ++ "] raven ready\r\n");

        var session: Session = .{};
        defer session.deinit(self.allocator);
        var arena_state = std.heap.ArenaAllocator.init(self.allocator);
        defer arena_state.deinit();

        while (session.state != .logout) {
            _ = arena_state.reset(.retain_capacity);
            const arena = arena_state.allocator();
            const input = proto.readCommand(arena, client.reader, w, self.config.max_message_size) catch |err| switch (err) {
                error.LiteralTooLarge => {
                    try w.writeAll("* BYE literal too large\r\n");
                    return;
                },
                else => return err,
            } orelse return;
            const text = switch (input) {
                .too_long => {
                    try w.writeAll("* BAD line too long\r\n");
                    continue;
                },
                .literal_refused => |tag| {
                    try w.print("{s} NO literal too large\r\n", .{tag});
                    continue;
                },
                .command => |text| text,
            };

            var p: proto.Parser = .{ .text = text, .arena = arena };
            const tag = p.atomWith("]") catch {
                try w.writeAll("* BAD missing tag\r\n");
                continue;
            };
            const ctx: Context = .{ .server = self, .io = fs_io, .session = &session, .w = w, .tag = tag };
            ctx.execute(&p) catch |err| switch (err) {
                error.Syntax => try ctx.bad("syntax error"),
                else => return err,
            };
        }
    }
};

const capabilities = "IMAP4rev1 LITERAL+";

const State = enum { not_authenticated, authenticated, selected, logout };

const Command = enum { capability, noop, logout, login, select, examine, list, fetch, store, expunge };

/// One command being executed.
const Context = struct {
    server: *ImapServer,
    io: Io,
    session: *Session,
    w: *Io.Writer,
    tag: []const u8,

    fn execute(ctx: Context, p: *proto.Parser) !void {
        try p.space();
        const name = try p.atom();
        var lower: [16]u8 = undefined;
        const command = if (name.len <= lower.len) std.meta.stringToEnum(Command, std.ascii.lowerString(&lower, name)) else null;
        const cmd = command orelse return ctx.bad("unknown command");

        const state = ctx.session.state;
        const allowed = switch (cmd) {
            .capability, .noop, .logout => true,
            .login => state == .not_authenticated,
            .select, .examine, .list => state == .authenticated or state == .selected,
            .fetch, .store, .expunge => state == .selected,
        };
        if (!allowed) return ctx.bad(if (state == .not_authenticated) "log in first" else "command not valid in this state");

        switch (cmd) {
            .capability => {
                try p.end();
                try ctx.w.writeAll("* CAPABILITY " ++ capabilities ++ "\r\n");
                try ctx.ok("CAPABILITY completed");
            },
            .noop => {
                try p.end();
                try ctx.ok("NOOP completed");
            },
            .logout => {
                try p.end();
                try ctx.w.writeAll("* BYE raven logging out\r\n");
                try ctx.ok("LOGOUT completed");
                ctx.session.state = .logout;
            },
            .login => try ctx.login(p),
            .select, .examine => try ctx.select(p, cmd == .examine),
            .list => try ctx.list(p),
            .fetch => try ctx.fetch(p),
            .store => try ctx.store(p),
            .expunge => try ctx.expunge(p),
        }
    }

    fn login(ctx: Context, p: *proto.Parser) !void {
        try p.space();
        const user = try p.astring();
        try p.space();
        const password = try p.astring();
        try p.end();

        const s = ctx.server;
        const identity = account_index.authenticate(s.allocator, ctx.io, s.storage, s.tenant_catalog, user, password) catch |err| switch (err) {
            error.AuthFailed => return ctx.no("[AUTHENTICATIONFAILED] authentication failed"),
            else => return err,
        };
        ctx.session.identity = identity;
        ctx.session.state = .authenticated;
        try ctx.ok("[CAPABILITY " ++ capabilities ++ "] LOGIN completed");
    }

    fn select(ctx: Context, p: *proto.Parser, read_only: bool) !void {
        try p.space();
        const mailbox = try p.astring();
        try p.end();

        const session = ctx.session;
        session.closeMailbox(ctx.server.allocator);
        if (!std.ascii.eqlIgnoreCase(mailbox, "INBOX")) return ctx.no("[NONEXISTENT] no such mailbox");

        const id = session.identity.?;
        session.messages = .fromOwnedSlice(try ctx.server.storage.listMailbox(ctx.io, ctx.server.allocator, id.tenant, id.domain, id.user));
        session.read_only = read_only;
        session.state = .selected;

        const w = ctx.w;
        try w.writeAll("* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)\r\n");
        try w.writeAll(if (read_only) "* OK [PERMANENTFLAGS ()] read-only\r\n" else "* OK [PERMANENTFLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)] limited\r\n");
        try w.print("* {d} EXISTS\r\n* 0 RECENT\r\n", .{session.messages.items.len});
        try w.writeAll("* OK [UIDVALIDITY 1] UIDs valid\r\n");
        try ctx.ok(if (read_only) "[READ-ONLY] EXAMINE completed" else "[READ-WRITE] SELECT completed");
    }

    fn list(ctx: Context, p: *proto.Parser) !void {
        try p.space();
        _ = try p.astring(); // reference name: only one level of mailboxes for now
        try p.space();
        const pattern = if (p.peek() == '"' or p.peek() == '{') try p.string() else try p.atomWith("]%*");
        try p.end();

        if (pattern.len == 0) {
            try ctx.w.writeAll("* LIST (\\Noselect) \"/\" \"\"\r\n");
        } else if (matchesPattern(pattern, "INBOX")) {
            try ctx.w.writeAll("* LIST (\\HasNoChildren) \"/\" INBOX\r\n");
        }
        try ctx.ok("LIST completed");
    }

    fn fetch(ctx: Context, p: *proto.Parser) !void {
        try p.space();
        const set = try p.sequenceSet();
        try p.space();
        _ = p.text[p.pos..]; // data items: always FLAGS and BODY[] until #14
        p.pos = p.text.len;

        const s = ctx.server;
        const messages = ctx.session.messages.items;
        for (messages, 1..) |message, number| {
            if (!set.contains(@intCast(number), @intCast(messages.len))) continue;
            const data = Storage.readMessage(ctx.io, s.allocator, message) catch |err| switch (err) {
                error.FileNotFound => return ctx.no("message no longer available"),
                else => return err,
            };
            defer s.allocator.free(data);
            const flags = try message.flags.format(s.allocator);
            defer s.allocator.free(flags);
            try ctx.w.print("* {d} FETCH (FLAGS {s} BODY[] {{{d}}}\r\n", .{ number, flags, data.len });
            try ctx.w.writeAll(data);
            try ctx.w.writeAll(")\r\n");
        }
        try ctx.ok("FETCH completed");
    }

    fn store(ctx: Context, p: *proto.Parser) !void {
        try p.space();
        const set = try p.sequenceSet();
        try p.space();
        const item = try p.atom();
        if (!std.ascii.eqlIgnoreCase(item, "+FLAGS") and !std.ascii.eqlIgnoreCase(item, "+FLAGS.SILENT")) return ctx.no("only +FLAGS is supported");
        try p.space();
        const added = try parseFlagList(p);
        try p.end();
        if (ctx.session.read_only) return ctx.no("[READ-ONLY] mailbox is read-only");

        const messages = ctx.session.messages.items;
        for (messages, 1..) |*message, number| {
            if (!set.contains(@intCast(number), @intCast(messages.len))) continue;
            Storage.setFlags(ctx.io, ctx.server.allocator, message, message.flags.merge(added)) catch |err| switch (err) {
                error.FileNotFound => return ctx.no("message no longer available"),
                else => return err,
            };
        }
        try ctx.ok("STORE completed");
    }

    fn expunge(ctx: Context, p: *proto.Parser) !void {
        try p.end();
        if (ctx.session.read_only) return ctx.no("[READ-ONLY] mailbox is read-only");
        const session = ctx.session;
        var i: usize = session.messages.items.len;
        while (i > 0) : (i -= 1) {
            if (!session.messages.items[i - 1].flags.deleted) continue;
            try Storage.deleteMessage(ctx.io, session.messages.items[i - 1]);
            try ctx.w.print("* {d} EXPUNGE\r\n", .{i});
            session.removeMessage(i - 1, ctx.server.allocator);
        }
        try ctx.ok("EXPUNGE completed");
    }

    fn ok(ctx: Context, text: []const u8) !void {
        try ctx.w.print("{s} OK {s}\r\n", .{ ctx.tag, text });
    }

    fn no(ctx: Context, text: []const u8) !void {
        try ctx.w.print("{s} NO {s}\r\n", .{ ctx.tag, text });
    }

    fn bad(ctx: Context, text: []const u8) !void {
        try ctx.w.print("{s} BAD {s}\r\n", .{ ctx.tag, text });
    }
};

const Session = struct {
    state: State = .not_authenticated,
    identity: ?Identity = null,
    messages: std.ArrayList(Message) = .empty,
    read_only: bool = false,

    fn closeMailbox(self: *Session, allocator: std.mem.Allocator) void {
        for (self.messages.items) |message| allocator.free(message.path);
        self.messages.deinit(allocator);
        self.messages = .empty;
        if (self.state == .selected) self.state = .authenticated;
    }

    fn removeMessage(self: *Session, index: usize, allocator: std.mem.Allocator) void {
        allocator.free(self.messages.orderedRemove(index).path);
    }

    fn deinit(self: *Session, allocator: std.mem.Allocator) void {
        self.closeMailbox(allocator);
        if (self.identity) |identity| identity.deinit(allocator);
        self.* = .{};
    }
};

/// `flag` or `(flag ...)`; keywords are accepted and ignored.
fn parseFlagList(p: *proto.Parser) !MessageFlags {
    var flags: MessageFlags = .{};
    const parenthesized = p.take('(');
    while (true) {
        if (parenthesized and p.take(')')) break;
        const system = p.take('\\');
        const name = try p.atom();
        if (system) {
            if (std.ascii.eqlIgnoreCase(name, "Seen")) flags.seen = true else if (std.ascii.eqlIgnoreCase(name, "Answered")) flags.answered = true else if (std.ascii.eqlIgnoreCase(name, "Flagged")) flags.flagged = true else if (std.ascii.eqlIgnoreCase(name, "Deleted")) flags.deleted = true else if (std.ascii.eqlIgnoreCase(name, "Draft")) flags.draft = true else return error.Syntax;
        }
        if (!parenthesized) break;
        if (p.take(')')) break;
        try p.space();
    }
    return flags;
}

/// LIST pattern match (RFC 3501 §6.3.8): `*` matches anything, `%` anything
/// but the hierarchy delimiter. INBOX is case-insensitive.
fn matchesPattern(pattern: []const u8, name: []const u8) bool {
    if (pattern.len == 0) return name.len == 0;
    switch (pattern[0]) {
        '*', '%' => {
            var i: usize = 0;
            while (i <= name.len) : (i += 1) {
                if (matchesPattern(pattern[1..], name[i..])) return true;
                if (i < name.len and pattern[0] == '%' and name[i] == '/') return false;
            }
            return false;
        },
        else => return name.len > 0 and std.ascii.toLower(pattern[0]) == std.ascii.toLower(name[0]) and matchesPattern(pattern[1..], name[1..]),
    }
}

test "flag lists" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var p: proto.Parser = .{ .text = "(\\Seen \\Flagged $Junk) \\Deleted", .arena = arena.allocator() };
    try std.testing.expectEqual(MessageFlags{ .seen = true, .flagged = true }, try parseFlagList(&p));
    try p.space();
    try std.testing.expectEqual(MessageFlags{ .deleted = true }, try parseFlagList(&p));
    var bad: proto.Parser = .{ .text = "(\\Bogus)", .arena = arena.allocator() };
    try std.testing.expectError(error.Syntax, parseFlagList(&bad));
}

test "list patterns" {
    try std.testing.expect(matchesPattern("*", "INBOX"));
    try std.testing.expect(matchesPattern("inbox", "INBOX"));
    try std.testing.expect(matchesPattern("IN%", "INBOX"));
    try std.testing.expect(matchesPattern("%", "INBOX"));
    try std.testing.expect(!matchesPattern("%", "a/b"));
    try std.testing.expect(matchesPattern("*", "a/b"));
    try std.testing.expect(!matchesPattern("Sent", "INBOX"));
}

/// Runs one IMAP session over fixed buffers against a mailbox holding two
/// messages for alice (password "pass word"). Returns the transcript.
fn testSession(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", tmp.sub_path[0..] });
    defer allocator.free(root);

    try account_index.writeTestAccounts(allocator, tmp.dir, &.{"alice"}, "pass word");
    try tmp.dir.createDirPath(std.testing.io, "tenants/acme/domains/example.com/users/alice/Maildir/new");
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "tenants/acme/domains/example.com/users/alice/Maildir/new/1.eml", .data = "Subject: hi\r\n\r\nhello\r\n" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "tenants/acme/domains/example.com/users/alice/Maildir/new/2.eml", .data = "Subject: two\r\n\r\n" });

    var catalog = try @import("tenant_index.zig").parseForTest(allocator, "tenant acme example.com\n");
    defer catalog.deinit(allocator);

    var server = ImapServer.init(allocator, .{ .data_dir = root }, Storage.init(root), &catalog);
    var in: Io.Reader = .fixed(input);
    var out: Io.Writer.Allocating = .init(allocator);
    defer out.deinit();
    var client: conn.Client = .{ .reader = &in, .writer = &out.writer };
    try server.handleClient(std.testing.io, &client);
    return out.toOwnedSlice();
}

test "imap session: states, quoting and literals" {
    const allocator = std.testing.allocator;
    const transcript = try testSession(allocator, "a0 SELECT INBOX\r\n" ++
        "a1 LOGIN alice@example.com \"wrong\"\r\n" ++
        "a2 LOGIN {17+}\r\nalice@example.com \"pass word\"\r\n" ++
        "a3 LOGIN alice@example.com x\r\n" ++
        "a4 BOGUS\r\n" ++
        "a5 SELECT\r\n" ++
        "a6 LIST \"\" *\r\n" ++
        "a7 LIST \"\" \"\"\r\n" ++
        "a8 SELECT Sent\r\n" ++
        "a9 LOGOUT\r\n");
    defer allocator.free(transcript);
    try std.testing.expectEqualStrings("* OK [CAPABILITY IMAP4rev1 LITERAL+] raven ready\r\n" ++
        "a0 BAD log in first\r\n" ++
        "a1 NO [AUTHENTICATIONFAILED] authentication failed\r\n" ++
        "a2 OK [CAPABILITY IMAP4rev1 LITERAL+] LOGIN completed\r\n" ++
        "a3 BAD command not valid in this state\r\n" ++
        "a4 BAD unknown command\r\n" ++
        "a5 BAD syntax error\r\n" ++
        "* LIST (\\HasNoChildren) \"/\" INBOX\r\na6 OK LIST completed\r\n" ++
        "* LIST (\\Noselect) \"/\" \"\"\r\na7 OK LIST completed\r\n" ++
        "a8 NO [NONEXISTENT] no such mailbox\r\n" ++
        "* BYE raven logging out\r\na9 OK LOGOUT completed\r\n", transcript);
}

test "imap session: select, fetch, store and expunge" {
    const allocator = std.testing.allocator;
    const transcript = try testSession(allocator, "a1 LOGIN alice@example.com \"pass word\"\r\n" ++
        "a2 EXAMINE INBOX\r\n" ++
        "a3 STORE 1 +FLAGS (\\Deleted)\r\n" ++
        "a4 SELECT inbox\r\n" ++
        "a5 FETCH 1:* BODY[]\r\n" ++
        "a6 STORE 1 +FLAGS.SILENT (\\Deleted \\Seen)\r\n" ++
        "a7 EXPUNGE\r\n" ++
        "a8 FETCH 1 BODY[]\r\n");
    defer allocator.free(transcript);
    const select = "* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)\r\n";
    try std.testing.expectEqualStrings("* OK [CAPABILITY IMAP4rev1 LITERAL+] raven ready\r\n" ++
        "a1 OK [CAPABILITY IMAP4rev1 LITERAL+] LOGIN completed\r\n" ++
        select ++ "* OK [PERMANENTFLAGS ()] read-only\r\n* 2 EXISTS\r\n* 0 RECENT\r\n* OK [UIDVALIDITY 1] UIDs valid\r\na2 OK [READ-ONLY] EXAMINE completed\r\n" ++
        "a3 NO [READ-ONLY] mailbox is read-only\r\n" ++
        select ++ "* OK [PERMANENTFLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)] limited\r\n* 2 EXISTS\r\n* 0 RECENT\r\n* OK [UIDVALIDITY 1] UIDs valid\r\na4 OK [READ-WRITE] SELECT completed\r\n" ++
        "* 1 FETCH (FLAGS () BODY[] {22}\r\nSubject: hi\r\n\r\nhello\r\n)\r\n* 2 FETCH (FLAGS () BODY[] {16}\r\nSubject: two\r\n\r\n)\r\na5 OK FETCH completed\r\n" ++
        "a6 OK STORE completed\r\n" ++
        "* 1 EXPUNGE\r\na7 OK EXPUNGE completed\r\n" ++
        "* 1 FETCH (FLAGS () BODY[] {16}\r\nSubject: two\r\n\r\n)\r\na8 OK FETCH completed\r\n", transcript);
}

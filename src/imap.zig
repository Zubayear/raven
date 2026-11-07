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
const mime = @import("mime.zig");

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

const Command = enum { capability, noop, logout, login, select, examine, list, fetch, store, expunge, uid };

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
            .fetch, .store, .expunge, .uid => state == .selected,
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
            .fetch => try ctx.fetch(p, .sequence),
            .store => try ctx.store(p, .sequence),
            .expunge => try ctx.expunge(p),
            .uid => {
                try p.space();
                const sub = try p.atom();
                if (std.ascii.eqlIgnoreCase(sub, "FETCH")) return ctx.fetch(p, .uid);
                if (std.ascii.eqlIgnoreCase(sub, "STORE")) return ctx.store(p, .uid);
                return ctx.bad("unknown UID command");
            },
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
        const opened = try ctx.server.storage.openMailbox(ctx.io, ctx.server.allocator, id.tenant, id.domain, id.user);
        session.messages = .fromOwnedSlice(opened.messages);
        session.uid_validity = opened.uid_validity;
        session.uid_next = opened.uid_next;
        session.read_only = read_only;
        session.state = .selected;

        const w = ctx.w;
        try w.writeAll("* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)\r\n");
        try w.writeAll(if (read_only) "* OK [PERMANENTFLAGS ()] read-only\r\n" else "* OK [PERMANENTFLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)] limited\r\n");
        try w.print("* {d} EXISTS\r\n* 0 RECENT\r\n", .{session.messages.items.len});
        try w.print("* OK [UIDVALIDITY {d}] UIDs valid\r\n* OK [UIDNEXT {d}] predicted next UID\r\n", .{ session.uid_validity, session.uid_next });
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

    fn fetch(ctx: Context, p: *proto.Parser, by: Addressing) !void {
        try p.space();
        const set = try p.sequenceSet();
        try p.space();
        const items = try parseFetchItems(p);
        try p.end();

        const allocator = ctx.server.allocator;
        var arena_state = std.heap.ArenaAllocator.init(allocator);
        defer arena_state.deinit();
        for (ctx.session.messages.items, 1..) |*message, number| {
            if (!ctx.session.inSet(set, by, number)) continue;
            _ = arena_state.reset(.retain_capacity);
            ctx.fetchOne(arena_state.allocator(), message, number, items, by) catch |err| switch (err) {
                error.FileNotFound => return ctx.no("message no longer available"),
                else => return err,
            };
        }
        try ctx.ok("FETCH completed");
    }

    fn fetchOne(ctx: Context, arena: std.mem.Allocator, message: *Message, number: usize, items: []const FetchItem, by: Addressing) !void {
        var needs_content = false;
        var marks_seen = false;
        var wants_flags = false;
        var wants_uid = false;
        for (items) |item| switch (item) {
            .flags => wants_flags = true,
            .uid => wants_uid = true,
            .internal_date, .rfc822_size => {},
            .rfc822, .rfc822_text => {
                needs_content = true;
                marks_seen = true;
            },
            .rfc822_header, .envelope, .body_structure, .body => needs_content = true,
            .section => |sec| {
                needs_content = true;
                if (!sec.peek) marks_seen = true;
            },
        };

        const raw = if (needs_content) try Storage.readMessage(ctx.io, arena, message.*) else "";
        const root = if (needs_content) try mime.parse(arena, raw) else undefined;

        // Reading a body sets \Seen, and the new flags go in this response.
        const flags_changed = marks_seen and !message.flags.seen and !ctx.session.read_only;
        if (flags_changed) {
            var flags = message.flags;
            flags.seen = true;
            try Storage.setFlags(ctx.io, ctx.server.allocator, message, flags);
        }

        const w = ctx.w;
        try w.print("* {d} FETCH (", .{number});
        var first = true;
        // UID FETCH responses always carry the UID (RFC 3501 §6.4.8).
        if (by == .uid and !wants_uid) try ctx.fetchItem(arena, &first, message, raw, &root, .uid);
        for (items) |item| try ctx.fetchItem(arena, &first, message, raw, &root, item);
        if (flags_changed and !wants_flags) try ctx.fetchItem(arena, &first, message, raw, &root, .flags);
        try w.writeAll(")\r\n");
    }

    fn fetchItem(ctx: Context, arena: std.mem.Allocator, first: *bool, message: *const Message, raw: []const u8, root: *const mime.Part, item: FetchItem) !void {
        const w = ctx.w;
        if (!first.*) try w.writeByte(' ');
        first.* = false;
        switch (item) {
            .flags => try w.print("FLAGS {s}", .{try message.flags.format(arena)}),
            .uid => try w.print("UID {d}", .{message.uid}),
            .internal_date => {
                try w.writeAll("INTERNALDATE \"");
                try writeInternalDate(w, message.internal_date);
                try w.writeByte('"');
            },
            .rfc822_size => try w.print("RFC822.SIZE {d}", .{message.size}),
            .envelope => {
                try w.writeAll("ENVELOPE ");
                try mime.writeEnvelope(arena, w, root.header);
            },
            .body_structure, .body => {
                try w.writeAll(if (item == .body) "BODY " else "BODYSTRUCTURE ");
                try mime.writeBodyStructure(arena, w, root, item == .body_structure);
            },
            .rfc822 => try writeLiteral(w, "RFC822", raw),
            .rfc822_header => try writeLiteral(w, "RFC822.HEADER", root.header),
            .rfc822_text => try writeLiteral(w, "RFC822.TEXT", root.body),
            .section => |sec| {
                var data = try sectionData(arena, raw, root, sec);
                try w.print("BODY[{s}]", .{sec.spec});
                if (sec.partial) |partial| {
                    try w.print("<{d}>", .{partial.origin});
                    data = data[@min(partial.origin, data.len)..];
                    data = data[0..@min(partial.count, data.len)];
                }
                try w.print(" {{{d}}}\r\n", .{data.len});
                try w.writeAll(data);
            },
        }
    }

    fn store(ctx: Context, p: *proto.Parser, by: Addressing) !void {
        try p.space();
        const set = try p.sequenceSet();
        try p.space();
        const item = try p.atom();
        if (!std.ascii.eqlIgnoreCase(item, "+FLAGS") and !std.ascii.eqlIgnoreCase(item, "+FLAGS.SILENT")) return ctx.no("only +FLAGS is supported");
        try p.space();
        const added = try parseFlagList(p);
        try p.end();
        if (ctx.session.read_only) return ctx.no("[READ-ONLY] mailbox is read-only");

        for (ctx.session.messages.items, 1..) |*message, number| {
            if (!ctx.session.inSet(set, by, number)) continue;
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

const FetchItem = union(enum) {
    flags,
    uid,
    internal_date,
    rfc822_size,
    envelope,
    body_structure,
    /// BODY without a section: the non-extensible body structure.
    body,
    rfc822,
    rfc822_header,
    rfc822_text,
    section: Section,
};

/// `BODY[...]` / `BODY.PEEK[...]` (RFC 3501 §6.4.5).
const Section = struct {
    /// Text between the brackets, echoed back in the response.
    spec: []const u8,
    /// Part numbers, e.g. 1.2; empty for the whole message.
    path: []const u32,
    text: enum { all, header, fields, fields_not, text, mime },
    fields: []const []const u8 = &.{},
    peek: bool,
    partial: ?struct { origin: u32, count: u32 } = null,
};

/// A data item, a parenthesized list, or ALL / FAST / FULL.
fn parseFetchItems(p: *proto.Parser) ![]const FetchItem {
    const fast: []const FetchItem = &.{ .flags, .internal_date, .rfc822_size };
    const all: []const FetchItem = &.{ .flags, .internal_date, .rfc822_size, .envelope };
    const full: []const FetchItem = &.{ .flags, .internal_date, .rfc822_size, .envelope, .body };
    if (!p.take('(')) {
        const start = p.pos;
        const word = fetchWord(p);
        if (std.ascii.eqlIgnoreCase(word, "ALL") and p.peek() != '[') return all;
        if (std.ascii.eqlIgnoreCase(word, "FAST")) return fast;
        if (std.ascii.eqlIgnoreCase(word, "FULL")) return full;
        p.pos = start;
        const items = try p.arena.alloc(FetchItem, 1);
        items[0] = try parseFetchItem(p);
        return items;
    }
    var items = std.ArrayList(FetchItem).empty;
    while (true) {
        try items.append(p.arena, try parseFetchItem(p));
        if (p.take(')')) return items.items;
        try p.space();
    }
}

fn fetchWord(p: *proto.Parser) []const u8 {
    const start = p.pos;
    while (p.peek()) |ch| : (p.pos += 1) if (!std.ascii.isAlphanumeric(ch) and ch != '.') break;
    return p.text[start..p.pos];
}

fn parseFetchItem(p: *proto.Parser) !FetchItem {
    const word = fetchWord(p);
    const simple = [_]struct { []const u8, FetchItem }{
        .{ "FLAGS", .flags },             .{ "UID", .uid },                     .{ "INTERNALDATE", .internal_date },
        .{ "RFC822.SIZE", .rfc822_size }, .{ "ENVELOPE", .envelope },           .{ "BODYSTRUCTURE", .body_structure },
        .{ "RFC822", .rfc822 },           .{ "RFC822.HEADER", .rfc822_header }, .{ "RFC822.TEXT", .rfc822_text },
    };
    for (simple) |entry| if (std.ascii.eqlIgnoreCase(word, entry[0])) return entry[1];

    const peek = std.ascii.eqlIgnoreCase(word, "BODY.PEEK");
    if (!peek and !std.ascii.eqlIgnoreCase(word, "BODY")) return error.Syntax;
    if (!p.take('[')) return if (peek) error.Syntax else .body;

    const spec_start = p.pos;
    var path = std.ArrayList(u32).empty;
    var text: @FieldType(Section, "text") = .all;
    var fields = std.ArrayList([]const u8).empty;
    while (p.peek()) |ch| {
        if (!std.ascii.isDigit(ch)) break;
        const n = try p.number();
        if (n == 0) return error.Syntax;
        try path.append(p.arena, n);
        if (!p.take('.')) break;
    }
    if (p.peek() != ']') {
        const name = fetchWord(p);
        if (std.ascii.eqlIgnoreCase(name, "HEADER")) {
            text = .header;
        } else if (std.ascii.eqlIgnoreCase(name, "TEXT")) {
            text = .text;
        } else if (std.ascii.eqlIgnoreCase(name, "MIME") and path.items.len != 0) {
            text = .mime;
        } else if (std.ascii.eqlIgnoreCase(name, "HEADER.FIELDS") or std.ascii.eqlIgnoreCase(name, "HEADER.FIELDS.NOT")) {
            text = if (name.len == "HEADER.FIELDS".len) .fields else .fields_not;
            try p.space();
            try p.expect('(');
            while (true) {
                try fields.append(p.arena, try p.astring());
                if (p.take(')')) break;
                try p.space();
            }
        } else return error.Syntax;
    }
    const spec = p.text[spec_start..p.pos];
    try p.expect(']');

    var section: Section = .{ .spec = spec, .path = path.items, .text = text, .fields = fields.items, .peek = peek };
    if (p.take('<')) {
        const origin = try p.number();
        try p.expect('.');
        const count = try p.number();
        if (count == 0) return error.Syntax;
        try p.expect('>');
        section.partial = .{ .origin = origin, .count = count };
    }
    return .{ .section = section };
}

fn sectionData(arena: std.mem.Allocator, raw: []const u8, root: *const mime.Part, sec: Section) ![]const u8 {
    if (sec.path.len == 0) return switch (sec.text) {
        .all => raw,
        .header => root.header,
        .text => root.body,
        .fields, .fields_not => filterFields(arena, root.header, sec.fields, sec.text == .fields_not),
        .mime => unreachable, // rejected while parsing
    };
    const part = mime.findPart(root, sec.path) orelse return "";
    // HEADER/TEXT below a part number address an attached message/rfc822.
    const message = part.message;
    return switch (sec.text) {
        .all => part.body,
        .mime => part.header,
        .header => if (message) |m| m.header else "",
        .text => if (message) |m| m.body else "",
        .fields, .fields_not => if (message) |m| filterFields(arena, m.header, sec.fields, sec.text == .fields_not) else "",
    };
}

/// The header fields named in `names` (or all others), ending with the
/// blank line, as HEADER.FIELDS[.NOT] requires.
fn filterFields(arena: std.mem.Allocator, header: []const u8, names: []const []const u8, exclude: bool) ![]const u8 {
    var out = std.ArrayList(u8).empty;
    var keep = false;
    var lines = std.mem.splitScalar(u8, header, '\n');
    while (lines.next()) |line| {
        const content = std.mem.trimEnd(u8, line, "\r");
        if (content.len == 0) continue;
        if (content[0] != ' ' and content[0] != '\t') {
            const colon = std.mem.indexOfScalar(u8, content, ':') orelse content.len;
            var listed = false;
            for (names) |name| listed = listed or std.ascii.eqlIgnoreCase(name, content[0..colon]);
            keep = listed != exclude;
        }
        if (keep) {
            try out.appendSlice(arena, content);
            try out.appendSlice(arena, "\r\n");
        }
    }
    try out.appendSlice(arena, "\r\n");
    return out.items;
}

fn writeLiteral(w: *Io.Writer, name: []const u8, data: []const u8) !void {
    try w.print("{s} {{{d}}}\r\n", .{ name, data.len });
    try w.writeAll(data);
}

/// IMAP date-time, e.g. `07-Nov-2026 09:35:47 +0000`.
fn writeInternalDate(w: *Io.Writer, seconds: u64) !void {
    const epoch: std.time.epoch.EpochSeconds = .{ .secs = seconds };
    const year_day = epoch.getEpochDay().calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    const time = epoch.getDaySeconds();
    const months = [_][]const u8{ "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
    try w.print("{d:0>2}-{s}-{d} {d:0>2}:{d:0>2}:{d:0>2} +0000", .{
        @as(u8, month_day.day_index) + 1, months[@backingInt(month_day.month) - 1], year_day.year,
        time.getHoursIntoDay(),           time.getMinutesIntoHour(),                time.getSecondsIntoMinute(),
    });
}

/// Whether a set names messages by sequence number or by UID.
const Addressing = enum { sequence, uid };

const Session = struct {
    state: State = .not_authenticated,
    identity: ?Identity = null,
    messages: std.ArrayList(Message) = .empty,
    uid_validity: u32 = 0,
    uid_next: u32 = 0,
    read_only: bool = false,

    /// Whether the message at `number` (1-based) is in `set`.
    fn inSet(self: *const Session, set: proto.SequenceSet, by: Addressing, number: usize) bool {
        const items = self.messages.items;
        return switch (by) {
            .sequence => set.contains(@intCast(number), @intCast(items.len)),
            .uid => set.contains(items[number - 1].uid, if (items.len == 0) 0 else items[items.len - 1].uid),
        };
    }

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
    // A fixed UIDVALIDITY keeps transcripts deterministic.
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "tenants/acme/domains/example.com/users/alice/Maildir/raven-uidlist", .data = "1234567890 1\n" });

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
        "a8 FETCH 1 BODY[]\r\n" ++
        "a9 UID FETCH 5:* BODY[]\r\n" ++
        "b1 UID STORE 1 +FLAGS (\\Seen)\r\n" ++
        "b2 UID BOGUS 1\r\n");
    defer allocator.free(transcript);
    const select = "* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)\r\n";
    try std.testing.expectEqualStrings("* OK [CAPABILITY IMAP4rev1 LITERAL+] raven ready\r\n" ++
        "a1 OK [CAPABILITY IMAP4rev1 LITERAL+] LOGIN completed\r\n" ++
        select ++ "* OK [PERMANENTFLAGS ()] read-only\r\n* 2 EXISTS\r\n* 0 RECENT\r\n* OK [UIDVALIDITY 1234567890] UIDs valid\r\n* OK [UIDNEXT 3] predicted next UID\r\na2 OK [READ-ONLY] EXAMINE completed\r\n" ++
        "a3 NO [READ-ONLY] mailbox is read-only\r\n" ++
        select ++ "* OK [PERMANENTFLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)] limited\r\n* 2 EXISTS\r\n* 0 RECENT\r\n* OK [UIDVALIDITY 1234567890] UIDs valid\r\n* OK [UIDNEXT 3] predicted next UID\r\na4 OK [READ-WRITE] SELECT completed\r\n" ++
        // Reading a body sets \\Seen and reports the new flags.
        "* 1 FETCH (BODY[] {22}\r\nSubject: hi\r\n\r\nhello\r\n FLAGS (\\Seen))\r\n* 2 FETCH (BODY[] {16}\r\nSubject: two\r\n\r\n FLAGS (\\Seen))\r\na5 OK FETCH completed\r\n" ++
        "a6 OK STORE completed\r\n" ++
        "* 1 EXPUNGE\r\na7 OK EXPUNGE completed\r\n" ++
        "* 1 FETCH (BODY[] {16}\r\nSubject: two\r\n\r\n)\r\na8 OK FETCH completed\r\n" ++
        "* 1 FETCH (UID 2 BODY[] {16}\r\nSubject: two\r\n\r\n)\r\na9 OK FETCH completed\r\n" ++
        "b1 OK STORE completed\r\n" ++ // UID 1 was expunged: nothing to do
        "b2 BAD unknown UID command\r\n", transcript);
}

test "imap session: fetch data items and sections" {
    const allocator = std.testing.allocator;
    const transcript = try testSession(allocator, "a1 LOGIN alice@example.com \"pass word\"\r\n" ++
        "a2 SELECT INBOX\r\n" ++
        "a3 FETCH 1 (UID FLAGS RFC822.SIZE INTERNALDATE ENVELOPE BODYSTRUCTURE)\r\n" ++
        "a4 FETCH 1 FAST\r\n" ++
        "a5 FETCH 1 (BODY.PEEK[HEADER.FIELDS (subject)] BODY.PEEK[TEXT] BODY.PEEK[1]<0.3> RFC822.HEADER)\r\n" ++
        "a6 FETCH 1 FLAGS\r\n" ++
        "a7 UID FETCH 1 (BODY[1.MIME] BODY.PEEK[2])\r\n" ++
        "a8 FETCH 1 BODY.PEEK\r\n" ++
        "a9 FETCH 1 (FLAGS\r\n");
    defer allocator.free(transcript);
    const end = std.mem.indexOf(u8, transcript, "a2 OK").?;
    try std.testing.expectEqualStrings("a2 OK [READ-WRITE] SELECT completed\r\n" ++
        "* 1 FETCH (UID 1 FLAGS () RFC822.SIZE 22 INTERNALDATE \"01-Jan-1970 00:00:01 +0000\" " ++
        "ENVELOPE (NIL \"hi\" NIL NIL NIL NIL NIL NIL NIL NIL) BODYSTRUCTURE (\"text\" \"plain\" (\"charset\" \"us-ascii\") NIL NIL \"7bit\" 7 1 NIL NIL NIL NIL))\r\n" ++
        "a3 OK FETCH completed\r\n" ++
        "* 1 FETCH (FLAGS () INTERNALDATE \"01-Jan-1970 00:00:01 +0000\" RFC822.SIZE 22)\r\na4 OK FETCH completed\r\n" ++
        "* 1 FETCH (BODY[HEADER.FIELDS (subject)] {15}\r\nSubject: hi\r\n\r\n BODY[TEXT] {7}\r\nhello\r\n BODY[1]<0> {3}\r\nhel RFC822.HEADER {15}\r\nSubject: hi\r\n\r\n)\r\n" ++
        "a5 OK FETCH completed\r\n" ++
        "* 1 FETCH (FLAGS ())\r\na6 OK FETCH completed\r\n" ++ // PEEK left \Seen alone
        "* 1 FETCH (UID 1 BODY[1.MIME] {15}\r\nSubject: hi\r\n\r\n BODY[2] {0}\r\n FLAGS (\\Seen))\r\na7 OK FETCH completed\r\n" ++
        "a8 BAD syntax error\r\n" ++
        "a9 BAD syntax error\r\n", transcript[end..]);
}

const std = @import("std");

const Io = std.Io;
const Config = @import("config.zig").Config;
const conn = @import("conn.zig");
const account_index = @import("account_index.zig");
const Identity = account_index.Identity;
const mailstore = @import("storage.zig");
const Storage = mailstore.Storage;
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

const capabilities = "IMAP4rev1 LITERAL+ UNSELECT MOVE SPECIAL-USE";

const State = enum { not_authenticated, authenticated, selected, logout };

const Command = enum { capability, noop, logout, login, select, examine, list, lsub, create, delete, rename, subscribe, unsubscribe, status, append, fetch, store, expunge, uid, check, close, unselect, copy, move, search };

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
            .select, .examine, .list, .lsub, .create, .delete, .rename, .subscribe, .unsubscribe, .status, .append => state == .authenticated or state == .selected,
            .fetch, .store, .expunge, .uid, .check, .close, .unselect, .copy, .move, .search => state == .selected,
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
            .list, .lsub => try ctx.list(p, cmd == .lsub),
            .create => try ctx.create(p),
            .delete => try ctx.delete(p),
            .rename => try ctx.rename(p),
            .subscribe, .unsubscribe => try ctx.subscribe(p, cmd == .subscribe),
            .status => try ctx.status(p),
            .append => try ctx.append(p),
            .copy, .move => try ctx.copy(p, .sequence, cmd == .move),
            .search => try ctx.search(p, .sequence),
            .fetch => try ctx.fetch(p, .sequence),
            .store => try ctx.store(p, .sequence),
            .expunge => {
                try p.end();
                if (ctx.session.read_only) return ctx.no("[READ-ONLY] mailbox is read-only");
                try ctx.expungeDeleted(true);
                try ctx.ok("EXPUNGE completed");
            },
            .check => {
                try p.end();
                try ctx.ok("CHECK completed"); // every change is already on disk
            },
            .close, .unselect => {
                try p.end();
                // CLOSE expunges silently (RFC 3501 §6.4.2); UNSELECT doesn't (RFC 3691).
                if (cmd == .close and !ctx.session.read_only) try ctx.expungeDeleted(false);
                ctx.session.closeMailbox(ctx.server.allocator);
                try ctx.ok(if (cmd == .close) "CLOSE completed" else "UNSELECT completed");
            },
            .uid => {
                try p.space();
                const sub = try p.atom();
                if (std.ascii.eqlIgnoreCase(sub, "FETCH")) return ctx.fetch(p, .uid);
                if (std.ascii.eqlIgnoreCase(sub, "STORE")) return ctx.store(p, .uid);
                if (std.ascii.eqlIgnoreCase(sub, "COPY")) return ctx.copy(p, .uid, false);
                if (std.ascii.eqlIgnoreCase(sub, "MOVE")) return ctx.copy(p, .uid, true);
                if (std.ascii.eqlIgnoreCase(sub, "SEARCH")) return ctx.search(p, .uid);
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
        ctx.session.maildir = try s.storage.maildirPath(s.allocator, identity.tenant, identity.domain, identity.user);
        ctx.session.state = .authenticated;
        try ensureDefaultFolders(ctx.io, s.allocator, ctx.session.maildir.?);
        try ctx.ok("[CAPABILITY " ++ capabilities ++ "] LOGIN completed");
    }

    fn select(ctx: Context, p: *proto.Parser, read_only: bool) !void {
        try p.space();
        const mailbox = try p.astring();
        try p.end();

        const session = ctx.session;
        session.closeMailbox(ctx.server.allocator);
        const path = try ctx.mailboxPath(mailbox) orelse return ctx.no("[NONEXISTENT] no such mailbox");
        defer ctx.server.allocator.free(path);
        const opened = try Storage.openMailbox(ctx.io, ctx.server.allocator, path);
        session.messages = .fromOwnedSlice(opened.messages);
        session.uid_validity = opened.uid_validity;
        session.uid_next = opened.uid_next;
        session.read_only = read_only;
        session.state = .selected;

        const w = ctx.w;
        try w.writeAll("* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)\r\n");
        try w.writeAll(if (read_only) "* OK [PERMANENTFLAGS ()] read-only\r\n" else "* OK [PERMANENTFLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)] limited\r\n");
        var recent: usize = 0;
        for (session.messages.items) |message| recent += @intFromBool(message.recent);
        try w.print("* {d} EXISTS\r\n* {d} RECENT\r\n", .{ session.messages.items.len, recent });
        try w.print("* OK [UIDVALIDITY {d}] UIDs valid\r\n* OK [UIDNEXT {d}] predicted next UID\r\n", .{ session.uid_validity, session.uid_next });
        try ctx.ok(if (read_only) "[READ-ONLY] EXAMINE completed" else "[READ-WRITE] SELECT completed");
    }

    /// The Maildir path of an existing mailbox, or null; the caller owns it.
    fn mailboxPath(ctx: Context, name: []const u8) !?[]u8 {
        const allocator = ctx.server.allocator;
        const maildir = ctx.session.maildir.?;
        if (!std.ascii.eqlIgnoreCase(name, "INBOX") and !mailstore.isFolderName(name)) return null;
        const path = try mailstore.folderPath(allocator, maildir, name);
        if (std.ascii.eqlIgnoreCase(name, "INBOX")) return path;
        Io.Dir.cwd().access(ctx.io, path, .{}) catch {
            allocator.free(path);
            return null;
        };
        return path;
    }

    /// LIST / LSUB (RFC 3501 §6.3.8–9) with special-use attributes (RFC 6154).
    fn list(ctx: Context, p: *proto.Parser, subscribed_only: bool) !void {
        try p.space();
        const reference = try p.astring();
        try p.space();
        const pattern = if (p.peek() == '"' or p.peek() == '{') try p.string() else try p.atomWith("]%*");
        try p.end();

        const verb = if (subscribed_only) "LSUB" else "LIST";
        if (pattern.len == 0) {
            try ctx.w.print("* {s} (\\Noselect) \"/\" \"\"\r\n", .{verb});
            return ctx.ok("LIST completed");
        }
        var arena_state = std.heap.ArenaAllocator.init(ctx.server.allocator);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        const full_pattern = try std.mem.concat(arena, u8, &.{ reference, pattern });
        const folders = try mailstore.listFolders(ctx.io, arena, ctx.session.maildir.?);
        const names = if (subscribed_only) try mailstore.readSubscriptions(ctx.io, arena, ctx.session.maildir.?) else try std.mem.concat(arena, []const u8, &.{ &.{"INBOX"}, folders });

        for (names) |name| {
            if (!matchesPattern(full_pattern, name)) continue;
            var children = false;
            for (folders) |folder| children = children or (std.mem.startsWith(u8, folder, name) and folder.len > name.len and folder[name.len] == '/');
            try ctx.w.print("* {s} ({s}", .{ verb, if (children) "\\HasChildren" else "\\HasNoChildren" });
            if (specialUse(name)) |attribute| try ctx.w.print(" {s}", .{attribute});
            try ctx.w.writeAll(") \"/\" ");
            try proto.writeString(ctx.w, name);
            try ctx.w.writeAll("\r\n");
        }
        try ctx.ok(if (subscribed_only) "LSUB completed" else "LIST completed");
    }

    fn create(ctx: Context, p: *proto.Parser) !void {
        try p.space();
        const name = std.mem.trimEnd(u8, try p.astring(), "/"); // a trailing delimiter is allowed
        try p.end();
        if (std.ascii.eqlIgnoreCase(name, "INBOX")) return ctx.no("[ALREADYEXISTS] INBOX always exists");
        if (!mailstore.isFolderName(name)) return ctx.no("[CANNOT] invalid mailbox name");
        mailstore.createFolder(ctx.io, ctx.server.allocator, ctx.session.maildir.?, name) catch |err| switch (err) {
            error.FolderExists => return ctx.no("[ALREADYEXISTS] mailbox exists"),
            else => return err,
        };
        try ctx.ok("CREATE completed");
    }

    fn delete(ctx: Context, p: *proto.Parser) !void {
        try p.space();
        const name = try p.astring();
        try p.end();
        if (std.ascii.eqlIgnoreCase(name, "INBOX")) return ctx.no("[CANNOT] INBOX cannot be deleted");
        if (!mailstore.isFolderName(name)) return ctx.no("[NONEXISTENT] no such mailbox");
        mailstore.deleteFolder(ctx.io, ctx.server.allocator, ctx.session.maildir.?, name) catch |err| switch (err) {
            error.NoSuchFolder => return ctx.no("[NONEXISTENT] no such mailbox"),
            else => return err,
        };
        try ctx.ok("DELETE completed");
    }

    fn rename(ctx: Context, p: *proto.Parser) !void {
        try p.space();
        const from = try p.astring();
        try p.space();
        const to = try p.astring();
        try p.end();
        if (std.ascii.eqlIgnoreCase(from, "INBOX") or std.ascii.eqlIgnoreCase(to, "INBOX")) return ctx.no("[CANNOT] INBOX cannot be renamed");
        if (!mailstore.isFolderName(from) or !mailstore.isFolderName(to)) return ctx.no("[CANNOT] invalid mailbox name");
        mailstore.renameFolder(ctx.io, ctx.server.allocator, ctx.session.maildir.?, from, to) catch |err| switch (err) {
            error.NoSuchFolder => return ctx.no("[NONEXISTENT] no such mailbox"),
            error.FolderExists => return ctx.no("[ALREADYEXISTS] target exists"),
            error.InvalidFolderName => return ctx.no("[CANNOT] invalid mailbox name"),
            else => return err,
        };
        try ctx.ok("RENAME completed");
    }

    fn subscribe(ctx: Context, p: *proto.Parser, add: bool) !void {
        try p.space();
        const name = try p.astring();
        try p.end();
        if (!std.ascii.eqlIgnoreCase(name, "INBOX") and !mailstore.isFolderName(name)) return ctx.no("[CANNOT] invalid mailbox name");

        var arena_state = std.heap.ArenaAllocator.init(ctx.server.allocator);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        var names = std.ArrayList([]const u8).empty;
        for (try mailstore.readSubscriptions(ctx.io, arena, ctx.session.maildir.?)) |existing| {
            if (!std.mem.eql(u8, existing, name)) try names.append(arena, existing);
        }
        if (add) try names.append(arena, name);
        try mailstore.writeSubscriptions(ctx.io, ctx.server.allocator, ctx.session.maildir.?, names.items);
        try ctx.ok(if (add) "SUBSCRIBE completed" else "UNSUBSCRIBE completed");
    }

    fn status(ctx: Context, p: *proto.Parser) !void {
        try p.space();
        const name = try p.astring();
        try p.space();
        try p.expect('(');
        var items = std.ArrayList([]const u8).empty;
        while (true) {
            try items.append(p.arena, try p.atom());
            if (p.take(')')) break;
            try p.space();
        }
        try p.end();

        const allocator = ctx.server.allocator;
        const path = try ctx.mailboxPath(name) orelse return ctx.no("[NONEXISTENT] no such mailbox");
        defer allocator.free(path);
        const opened = try Storage.openMailbox(ctx.io, allocator, path);
        defer mailstore.freeMessages(allocator, opened.messages);
        var unseen: usize = 0;
        var recent: usize = 0;
        for (opened.messages) |message| {
            unseen += @intFromBool(!message.flags.seen);
            recent += @intFromBool(message.recent);
        }

        try ctx.w.writeAll("* STATUS ");
        try proto.writeString(ctx.w, name);
        try ctx.w.writeAll(" (");
        for (items.items, 0..) |item, i| {
            if (i != 0) try ctx.w.writeByte(' ');
            const value: usize = if (std.ascii.eqlIgnoreCase(item, "MESSAGES")) opened.messages.len else if (std.ascii.eqlIgnoreCase(item, "RECENT")) recent else if (std.ascii.eqlIgnoreCase(item, "UIDNEXT")) opened.uid_next else if (std.ascii.eqlIgnoreCase(item, "UIDVALIDITY")) opened.uid_validity else if (std.ascii.eqlIgnoreCase(item, "UNSEEN")) unseen else return error.Syntax;
            try ctx.w.print("{s} {d}", .{ item, value });
        }
        try ctx.w.writeAll(")\r\n");
        try ctx.ok("STATUS completed");
    }

    /// `APPEND mailbox [(flags)] ["date-time"] message` (RFC 3501 §6.3.11).
    fn append(ctx: Context, p: *proto.Parser) !void {
        try p.space();
        const name = try p.astring();
        try p.space();
        var flags: ?MessageFlags = null;
        if (p.peek() == '(') {
            flags = try parseFlagList(p);
            try p.space();
        }
        var date: ?u64 = null;
        if (p.peek() == '"') {
            date = parseDateTime(try p.string()) orelse return error.Syntax;
            try p.space();
        }
        const message = try p.string();
        try p.end();

        const allocator = ctx.server.allocator;
        const path = try ctx.mailboxPath(name) orelse return ctx.no("[TRYCREATE] no such mailbox");
        defer allocator.free(path);
        allocator.free(try mailstore.deliverTo(ctx.io, allocator, path, "", message, .{ .flags = flags, .date = date }));
        try ctx.ok("APPEND completed");
    }

    /// COPY / MOVE (RFC 6851), by sequence number or UID. Flags and arrival
    /// dates travel with the messages.
    fn copy(ctx: Context, p: *proto.Parser, by: Addressing, move: bool) !void {
        try p.space();
        const set = try p.sequenceSet();
        try p.space();
        const name = try p.astring();
        try p.end();
        if (move and ctx.session.read_only) return ctx.no("[READ-ONLY] mailbox is read-only");

        const allocator = ctx.server.allocator;
        const path = try ctx.mailboxPath(name) orelse return ctx.no("[TRYCREATE] no such mailbox");
        defer allocator.free(path);
        for (ctx.session.messages.items, 1..) |message, number| {
            if (!ctx.session.inSet(set, by, number)) continue;
            const data = Storage.readMessage(ctx.io, allocator, message) catch |err| switch (err) {
                error.FileNotFound => return ctx.no("message no longer available"),
                else => return err,
            };
            defer allocator.free(data);
            allocator.free(try mailstore.deliverTo(ctx.io, allocator, path, "", data, .{ .flags = message.flags, .date = message.internal_date }));
        }
        if (move) {
            const session = ctx.session;
            var i: usize = session.messages.items.len;
            while (i > 0) : (i -= 1) {
                if (!session.inSet(set, by, i)) continue;
                try Storage.deleteMessage(ctx.io, session.messages.items[i - 1]);
                try ctx.w.print("* {d} EXPUNGE\r\n", .{i});
                session.removeMessage(i - 1, allocator);
            }
        }
        try ctx.ok(if (move) "MOVE completed" else "COPY completed");
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
                error.TooManyParts => return ctx.no("[LIMIT] message structure too complex"),
                else => return err,
            };
        }
        try ctx.ok("FETCH completed");
    }

    fn fetchOne(ctx: Context, arena: std.mem.Allocator, message: *Message, number: usize, items: []const FetchItem, by: Addressing) !void {
        var needs_content = false;
        var needs_tree = false; // the full MIME tree, not just header and body
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
            .rfc822_header, .envelope => needs_content = true,
            .body_structure, .body => {
                needs_content = true;
                needs_tree = true;
            },
            .section => |sec| {
                needs_content = true;
                needs_tree = needs_tree or sec.path.len != 0;
                if (!sec.peek) marks_seen = true;
            },
        };

        const raw = if (needs_content) try Storage.readMessage(ctx.io, arena, message.*) else "";
        const root = if (!needs_content) undefined else if (needs_tree) try mime.parse(arena, raw) else try mime.parseShallow(arena, raw);

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
            .flags => try writeFlags(w, message),
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

    /// `STORE set [+|-]FLAGS[.SILENT] flags` (RFC 3501 §6.4.6).
    fn store(ctx: Context, p: *proto.Parser, by: Addressing) !void {
        try p.space();
        const set = try p.sequenceSet();
        try p.space();
        var item = try p.atom();
        const mode: enum { replace, add, remove } = switch (item[0]) {
            '+' => .add,
            '-' => .remove,
            else => .replace,
        };
        if (mode != .replace) item = item[1..];
        const silent = std.ascii.endsWithIgnoreCase(item, ".SILENT");
        if (silent) item = item[0 .. item.len - ".SILENT".len];
        if (!std.ascii.eqlIgnoreCase(item, "FLAGS")) return error.Syntax;
        try p.space();
        const given = try parseFlagList(p);
        try p.end();
        if (ctx.session.read_only) return ctx.no("[READ-ONLY] mailbox is read-only");

        for (ctx.session.messages.items, 1..) |*message, number| {
            if (!ctx.session.inSet(set, by, number)) continue;
            const flags = switch (mode) {
                .replace => given,
                .add => message.flags.merge(given),
                .remove => message.flags.without(given),
            };
            Storage.setFlags(ctx.io, ctx.server.allocator, message, flags) catch |err| switch (err) {
                error.FileNotFound => return ctx.no("message no longer available"),
                else => return err,
            };
            if (silent) continue;
            try ctx.w.print("* {d} FETCH (", .{number});
            if (by == .uid) try ctx.w.print("UID {d} ", .{message.uid});
            try writeFlags(ctx.w, message);
            try ctx.w.writeAll(")\r\n");
        }
        try ctx.ok("STORE completed");
    }

    /// Deletes every \\Deleted message, reporting each one unless `announce`
    /// is false. Highest first, so the reported numbers stay valid.
    fn expungeDeleted(ctx: Context, announce: bool) !void {
        const session = ctx.session;
        var i: usize = session.messages.items.len;
        while (i > 0) : (i -= 1) {
            if (!session.messages.items[i - 1].flags.deleted) continue;
            try Storage.deleteMessage(ctx.io, session.messages.items[i - 1]);
            if (announce) try ctx.w.print("* {d} EXPUNGE\r\n", .{i});
            session.removeMessage(i - 1, ctx.server.allocator);
        }
    }

    /// SEARCH / UID SEARCH (RFC 3501 §6.4.4).
    fn search(ctx: Context, p: *proto.Parser, by: Addressing) !void {
        try p.space();
        if (p.text.len - p.pos >= 8 and std.ascii.eqlIgnoreCase(p.text[p.pos..][0..8], "CHARSET ")) {
            p.pos += 8;
            const charset = try p.astring();
            if (!std.ascii.eqlIgnoreCase(charset, "UTF-8") and !std.ascii.eqlIgnoreCase(charset, "US-ASCII")) return ctx.no("[BADCHARSET (US-ASCII UTF-8)] unsupported charset");
            try p.space();
        }
        const query = try parseSearchKeys(p, ')');
        try p.end();

        const allocator = ctx.server.allocator;
        var arena_state = std.heap.ArenaAllocator.init(allocator);
        defer arena_state.deinit();
        const messages = ctx.session.messages.items;
        try ctx.w.writeAll("* SEARCH");
        for (messages, 1..) |message, number| {
            _ = arena_state.reset(.retain_capacity);
            var view: SearchView = .{ .session = ctx.session, .number = number, .message = &message, .io = ctx.io, .arena = arena_state.allocator() };
            const matched = view.matchesAll(query) catch |err| switch (err) {
                error.FileNotFound => continue, // vanished under a concurrent session
                else => return err,
            };
            if (matched) try ctx.w.print(" {d}", .{if (by == .uid) message.uid else number});
        }
        try ctx.w.writeAll("\r\n");
        try ctx.ok("SEARCH completed");
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

/// `FLAGS (...)` including the session-only \\Recent.
fn writeFlags(w: *Io.Writer, message: *const Message) !void {
    const f = message.flags;
    try w.writeAll("FLAGS (");
    var first = true;
    for ([_]struct { bool, []const u8 }{ .{ f.seen, "\\Seen" }, .{ f.answered, "\\Answered" }, .{ f.flagged, "\\Flagged" }, .{ f.deleted, "\\Deleted" }, .{ f.draft, "\\Draft" }, .{ message.recent, "\\Recent" } }) |flag| {
        if (!flag[0]) continue;
        if (!first) try w.writeByte(' ');
        first = false;
        try w.writeAll(flag[1]);
    }
    try w.writeByte(')');
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

const SearchKey = union(enum) {
    all,
    set: proto.SequenceSet,
    uid_set: proto.SequenceSet,
    flag: struct { name: enum { seen, answered, flagged, deleted, draft }, set: bool },
    recent: bool,
    new,
    header: struct { field: []const u8, needle: []const u8 },
    body: []const u8,
    text: []const u8,
    date: struct { op: enum { before, on, since }, day: u64, sent: bool },
    size: struct { larger: bool, bytes: u64 },
    not: *const SearchKey,
    @"or": [2]*const SearchKey,
    group: []const SearchKey,
};

/// `key *(SP key)` up to end of input or `close`; an implicit AND.
fn parseSearchKeys(p: *proto.Parser, close: u8) proto.Parser.Error![]const SearchKey {
    var keys = std.ArrayList(SearchKey).empty;
    while (true) {
        try keys.append(p.arena, try parseSearchKey(p));
        if (p.atEnd() or p.peek() == close) return keys.items;
        try p.space();
    }
}

fn parseSearchKey(p: *proto.Parser) proto.Parser.Error!SearchKey {
    if (p.take('(')) {
        const keys = try parseSearchKeys(p, ')');
        try p.expect(')');
        return .{ .group = keys };
    }
    if (p.peek()) |ch| if (std.ascii.isDigit(ch) or ch == '*') return .{ .set = try p.sequenceSet() };

    const word = try p.atom();
    const flags = [_]struct { []const u8, @FieldType(@FieldType(SearchKey, "flag"), "name"), bool }{
        .{ "SEEN", .seen, true },         .{ "UNSEEN", .seen, false },
        .{ "ANSWERED", .answered, true }, .{ "UNANSWERED", .answered, false },
        .{ "FLAGGED", .flagged, true },   .{ "UNFLAGGED", .flagged, false },
        .{ "DELETED", .deleted, true },   .{ "UNDELETED", .deleted, false },
        .{ "DRAFT", .draft, true },       .{ "UNDRAFT", .draft, false },
    };
    for (flags) |f| if (std.ascii.eqlIgnoreCase(word, f[0])) return .{ .flag = .{ .name = f[1], .set = f[2] } };
    for ([_][]const u8{ "FROM", "TO", "CC", "BCC", "SUBJECT" }) |field| {
        if (std.ascii.eqlIgnoreCase(word, field)) {
            try p.space();
            return .{ .header = .{ .field = field, .needle = try p.astring() } };
        }
    }
    const dates = [_]struct { []const u8, @FieldType(@FieldType(SearchKey, "date"), "op"), bool }{
        .{ "BEFORE", .before, false },    .{ "ON", .on, false },    .{ "SINCE", .since, false },
        .{ "SENTBEFORE", .before, true }, .{ "SENTON", .on, true }, .{ "SENTSINCE", .since, true },
    };
    for (dates) |d| {
        if (std.ascii.eqlIgnoreCase(word, d[0])) {
            try p.space();
            const day = parseSearchDate(try p.astring()) orelse return error.Syntax;
            return .{ .date = .{ .op = d[1], .day = day, .sent = d[2] } };
        }
    }

    const Simple = enum { all, recent, old, new, header, body, text, larger, smaller, not, @"or", uid };
    var lower: [8]u8 = undefined;
    const simple = if (word.len <= lower.len) std.meta.stringToEnum(Simple, std.ascii.lowerString(&lower, word)) else null;
    switch (simple orelse return error.Syntax) {
        .all => return .all,
        .recent => return .{ .recent = true },
        .old => return .{ .recent = false },
        .new => return .new,
        .header => {
            try p.space();
            const field = try p.astring();
            try p.space();
            return .{ .header = .{ .field = field, .needle = try p.astring() } };
        },
        .body, .text => {
            try p.space();
            const needle = try p.astring();
            return if (simple.? == .body) .{ .body = needle } else .{ .text = needle };
        },
        .larger, .smaller => {
            try p.space();
            return .{ .size = .{ .larger = simple.? == .larger, .bytes = try p.number() } };
        },
        .not => {
            try p.space();
            const key = try p.arena.create(SearchKey);
            key.* = try parseSearchKey(p);
            return .{ .not = key };
        },
        .@"or" => {
            const keys = try p.arena.alloc(SearchKey, 2);
            for (keys) |*key| {
                try p.space();
                key.* = try parseSearchKey(p);
            }
            return .{ .@"or" = .{ &keys[0], &keys[1] } };
        },
        .uid => {
            try p.space();
            return .{ .uid_set = try p.sequenceSet() };
        },
    }
}

/// `7-Nov-2026` (quoted or not) as days since the epoch.
fn parseSearchDate(text: []const u8) ?u64 {
    var buf: [48]u8 = undefined;
    const date_time = std.fmt.bufPrint(&buf, "{s} 00:00:00 +0000", .{text}) catch return null;
    return (parseDateTime(date_time) orelse return null) / std.time.s_per_day;
}

/// One message under test; content is read only if a key needs it.
const SearchView = struct {
    session: *const Session,
    number: usize,
    message: *const Message,
    io: Io,
    arena: std.mem.Allocator,
    part: ?mime.Part = null,

    fn content(view: *SearchView) !mime.Part {
        if (view.part == null) view.part = try mime.parseShallow(view.arena, try Storage.readMessage(view.io, view.arena, view.message.*));
        return view.part.?;
    }

    fn matchesAll(view: *SearchView, keys: []const SearchKey) anyerror!bool {
        for (keys) |key| if (!try view.matches(key)) return false;
        return true;
    }

    fn matches(view: *SearchView, key: SearchKey) anyerror!bool {
        const m = view.message;
        return switch (key) {
            .all => true,
            .set => |set| view.session.inSet(set, .sequence, view.number),
            .uid_set => |set| view.session.inSet(set, .uid, view.number),
            .flag => |f| f.set == switch (f.name) {
                .seen => m.flags.seen,
                .answered => m.flags.answered,
                .flagged => m.flags.flagged,
                .deleted => m.flags.deleted,
                .draft => m.flags.draft,
            },
            .recent => |recent| m.recent == recent,
            .new => m.recent and !m.flags.seen,
            .header => |h| blk: {
                const value = try mime.field(view.arena, (try view.content()).header, h.field) orelse break :blk false;
                break :blk containsIgnoreCase(value, h.needle);
            },
            .body => |needle| containsIgnoreCase((try view.content()).body, needle),
            .text => |needle| blk: {
                const part = try view.content();
                break :blk containsIgnoreCase(part.header, needle) or containsIgnoreCase(part.body, needle);
            },
            .date => |d| blk: {
                const day = if (d.sent) sentDay(try mime.field(view.arena, (try view.content()).header, "Date")) orelse break :blk false else m.internal_date / std.time.s_per_day;
                break :blk switch (d.op) {
                    .before => day < d.day,
                    .on => day == d.day,
                    .since => day >= d.day,
                };
            },
            .size => |s| if (s.larger) m.size > s.bytes else m.size < s.bytes,
            .not => |inner| !try view.matches(inner.*),
            .@"or" => |pair| try view.matches(pair[0].*) or try view.matches(pair[1].*),
            .group => |keys| try view.matchesAll(keys),
        };
    }
};

/// The day of an RFC 5322 Date header, ignoring time and zone (RFC 3501
/// §6.4.4), e.g. `Sat, 07 Nov 2026 09:35:47 +0000`.
fn sentDay(date: ?[]const u8) ?u64 {
    var text = date orelse return null;
    if (std.mem.indexOfScalar(u8, text, ',')) |comma| text = text[comma + 1 ..];
    var fields = std.mem.tokenizeScalar(u8, text, ' ');
    const day = fields.next() orelse return null;
    const month = fields.next() orelse return null;
    const year = fields.next() orelse return null;
    var buf: [32]u8 = undefined;
    const joined = std.fmt.bufPrint(&buf, "{s}-{s}-{s} 00:00:00 +0000", .{ day, month, year }) catch return null;
    return (parseDateTime(joined) orelse return null) / std.time.s_per_day;
}

fn containsIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    return std.ascii.findIgnoreCase(haystack, needle) != null;
}

/// Whether a set names messages by sequence number or by UID.
const Addressing = enum { sequence, uid };

const Session = struct {
    state: State = .not_authenticated,
    identity: ?Identity = null,
    messages: std.ArrayList(Message) = .empty,
    /// The user's INBOX Maildir, set at login.
    maildir: ?[]u8 = null,
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
        if (self.maildir) |path| allocator.free(path);
        self.* = .{};
    }
};

const default_folders = [_][]const u8{ "Sent", "Drafts", "Trash", "Junk" };

fn specialUse(name: []const u8) ?[]const u8 {
    for (default_folders) |folder| {
        if (std.mem.eql(u8, name, folder)) return switch (folder[0]) {
            'S' => "\\Sent",
            'D' => "\\Drafts",
            'T' => "\\Trash",
            else => "\\Junk",
        };
    }
    return null;
}

/// Creates the special-use folders on first login and subscribes to them.
fn ensureDefaultFolders(io: Io, allocator: std.mem.Allocator, maildir: []const u8) !void {
    const subscriptions = try std.fs.path.join(allocator, &.{ maildir, "subscriptions" });
    defer allocator.free(subscriptions);
    if (Io.Dir.cwd().access(io, subscriptions, .{})) |_| return else |_| {}
    for (default_folders) |folder| mailstore.createFolder(io, allocator, maildir, folder) catch |err| switch (err) {
        error.FolderExists => {},
        else => return err,
    };
    try mailstore.writeSubscriptions(io, allocator, maildir, &(.{"INBOX"} ++ default_folders));
}

/// IMAP date-time, e.g. ` 7-Nov-2026 09:35:47 +0100`, as Unix seconds.
fn parseDateTime(text: []const u8) ?u64 {
    const months = [_][]const u8{ "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
    var fields = std.mem.tokenizeAny(u8, text, " -:");
    const day = std.fmt.parseInt(u32, fields.next() orelse return null, 10) catch return null;
    const month_name = fields.next() orelse return null;
    const year = std.fmt.parseInt(i64, fields.next() orelse return null, 10) catch return null;
    const hour = std.fmt.parseInt(i64, fields.next() orelse return null, 10) catch return null;
    const minute = std.fmt.parseInt(i64, fields.next() orelse return null, 10) catch return null;
    const second = std.fmt.parseInt(i64, fields.next() orelse return null, 10) catch return null;
    const zone = fields.next() orelse return null;
    if (fields.next() != null or zone.len != 5 or (zone[0] != '+' and zone[0] != '-')) return null;
    const zone_hours = std.fmt.parseInt(i64, zone[1..3], 10) catch return null;
    const zone_minutes = std.fmt.parseInt(i64, zone[3..5], 10) catch return null;
    var month: i64 = 0;
    for (months, 1..) |name, i| {
        if (std.ascii.eqlIgnoreCase(name, month_name)) month = @intCast(i);
    }
    if (month == 0 or day == 0 or day > 31 or hour > 23 or minute > 59 or second > 60) return null;

    // Days from civil (Howard Hinnant's algorithm).
    const y = year - @intFromBool(month <= 2);
    const era = @divFloor(y, 400);
    const yoe = y - era * 400;
    const doy = @divFloor(153 * (month + (if (month > 2) @as(i64, -3) else 9)) + 2, 5) + day - 1;
    const doe = yoe * 365 + @divFloor(yoe, 4) - @divFloor(yoe, 100) + doy;
    const days = era * 146097 + doe - 719468;
    const offset = (zone_hours * 3600 + zone_minutes * 60) * @as(i64, if (zone[0] == '-') -1 else 1);
    const seconds = days * 86400 + hour * 3600 + minute * 60 + second - offset;
    return if (seconds < 0) null else @intCast(seconds);
}

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
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "tenants/acme/domains/example.com/users/alice/Maildir/new/0000000001.fixture", .data = "Subject: hi\r\n\r\nhello\r\n" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "tenants/acme/domains/example.com/users/alice/Maildir/new/0000000002.fixture", .data = "Subject: two\r\n\r\n" });
    // INTERNALDATE comes from the mtime: pin it to 1970-01-01 00:00:01.
    for ([_][]const u8{ "0000000001.fixture", "0000000002.fixture" }) |name| {
        const path = try std.fmt.allocPrint(allocator, "tenants/acme/domains/example.com/users/alice/Maildir/new/{s}", .{name});
        defer allocator.free(path);
        const file = try tmp.dir.openFile(std.testing.io, path, .{ .mode = .read_write });
        defer file.close(std.testing.io);
        try file.setTimestamps(std.testing.io, .{ .modify_timestamp = .{ .new = .{ .nanoseconds = std.time.ns_per_s } } });
    }
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
        "a8 SELECT Nope\r\n" ++
        "a9 LOGOUT\r\n");
    defer allocator.free(transcript);
    try std.testing.expectEqualStrings("* OK [CAPABILITY IMAP4rev1 LITERAL+ UNSELECT MOVE SPECIAL-USE] raven ready\r\n" ++
        "a0 BAD log in first\r\n" ++
        "a1 NO [AUTHENTICATIONFAILED] authentication failed\r\n" ++
        "a2 OK [CAPABILITY IMAP4rev1 LITERAL+ UNSELECT MOVE SPECIAL-USE] LOGIN completed\r\n" ++
        "a3 BAD command not valid in this state\r\n" ++
        "a4 BAD unknown command\r\n" ++
        "a5 BAD syntax error\r\n" ++
        "* LIST (\\HasNoChildren) \"/\" \"INBOX\"\r\n* LIST (\\HasNoChildren \\Drafts) \"/\" \"Drafts\"\r\n" ++
        "* LIST (\\HasNoChildren \\Junk) \"/\" \"Junk\"\r\n* LIST (\\HasNoChildren \\Sent) \"/\" \"Sent\"\r\n" ++
        "* LIST (\\HasNoChildren \\Trash) \"/\" \"Trash\"\r\na6 OK LIST completed\r\n" ++
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
    try std.testing.expectEqualStrings("* OK [CAPABILITY IMAP4rev1 LITERAL+ UNSELECT MOVE SPECIAL-USE] raven ready\r\n" ++
        "a1 OK [CAPABILITY IMAP4rev1 LITERAL+ UNSELECT MOVE SPECIAL-USE] LOGIN completed\r\n" ++
        select ++ "* OK [PERMANENTFLAGS ()] read-only\r\n* 2 EXISTS\r\n* 2 RECENT\r\n* OK [UIDVALIDITY 1234567890] UIDs valid\r\n* OK [UIDNEXT 3] predicted next UID\r\na2 OK [READ-ONLY] EXAMINE completed\r\n" ++
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
        "* 1 FETCH (UID 1 FLAGS (\\Recent) RFC822.SIZE 22 INTERNALDATE \"01-Jan-1970 00:00:01 +0000\" " ++
        "ENVELOPE (NIL \"hi\" NIL NIL NIL NIL NIL NIL NIL NIL) BODYSTRUCTURE (\"text\" \"plain\" (\"charset\" \"us-ascii\") NIL NIL \"7bit\" 7 1 NIL NIL NIL NIL))\r\n" ++
        "a3 OK FETCH completed\r\n" ++
        "* 1 FETCH (FLAGS (\\Recent) INTERNALDATE \"01-Jan-1970 00:00:01 +0000\" RFC822.SIZE 22)\r\na4 OK FETCH completed\r\n" ++
        "* 1 FETCH (BODY[HEADER.FIELDS (subject)] {15}\r\nSubject: hi\r\n\r\n BODY[TEXT] {7}\r\nhello\r\n BODY[1]<0> {3}\r\nhel RFC822.HEADER {15}\r\nSubject: hi\r\n\r\n)\r\n" ++
        "a5 OK FETCH completed\r\n" ++
        "* 1 FETCH (FLAGS (\\Recent))\r\na6 OK FETCH completed\r\n" ++ // PEEK left \Seen alone
        "* 1 FETCH (UID 1 BODY[1.MIME] {15}\r\nSubject: hi\r\n\r\n BODY[2] {0}\r\n FLAGS (\\Seen \\Recent))\r\na7 OK FETCH completed\r\n" ++
        "a8 BAD syntax error\r\n" ++
        "a9 BAD syntax error\r\n", transcript[end..]);
}

test "imap session: store modes, recent, close and unselect" {
    const allocator = std.testing.allocator;
    const transcript = try testSession(allocator, "a1 LOGIN alice@example.com \"pass word\"\r\n" ++
        "a2 SELECT INBOX\r\n" ++
        "a3 STORE 1 FLAGS (\\Flagged)\r\n" ++
        "a4 STORE 1 +FLAGS (\\Seen \\Answered)\r\n" ++
        "a5 STORE 1 -FLAGS (\\Flagged)\r\n" ++
        "a6 UID STORE 2 FLAGS.SILENT (\\Deleted)\r\n" ++
        "a7 UID STORE 1:* +FLAGS (\\Draft)\r\n" ++
        "a8 STORE 1 BOGUS (\\Seen)\r\n" ++
        "a9 CHECK\r\n" ++
        "b1 UNSELECT\r\n" ++
        "b2 FETCH 1 FLAGS\r\n" ++
        "b3 SELECT INBOX\r\n" ++
        "b4 CLOSE\r\n" ++
        "b5 SELECT INBOX\r\n");
    defer allocator.free(transcript);
    const end = std.mem.indexOf(u8, transcript, "a2 OK").?;
    try std.testing.expect(std.mem.indexOf(u8, transcript[0..end], "* 2 RECENT\r\n") != null);
    try std.testing.expectEqualStrings("a2 OK [READ-WRITE] SELECT completed\r\n" ++
        "* 1 FETCH (FLAGS (\\Flagged \\Recent))\r\na3 OK STORE completed\r\n" ++
        "* 1 FETCH (FLAGS (\\Seen \\Answered \\Flagged \\Recent))\r\na4 OK STORE completed\r\n" ++
        "* 1 FETCH (FLAGS (\\Seen \\Answered \\Recent))\r\na5 OK STORE completed\r\n" ++
        "a6 OK STORE completed\r\n" ++
        "* 1 FETCH (UID 1 FLAGS (\\Seen \\Answered \\Draft \\Recent))\r\n* 2 FETCH (UID 2 FLAGS (\\Deleted \\Draft \\Recent))\r\na7 OK STORE completed\r\n" ++
        "a8 BAD syntax error\r\n" ++
        "a9 OK CHECK completed\r\n" ++
        "b1 OK UNSELECT completed\r\n" ++
        "b2 BAD command not valid in this state\r\n" ++
        // UNSELECT kept the \Deleted message; nothing is recent any more.
        "* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)\r\n* OK [PERMANENTFLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)] limited\r\n" ++
        "* 2 EXISTS\r\n* 0 RECENT\r\n* OK [UIDVALIDITY 1234567890] UIDs valid\r\n* OK [UIDNEXT 3] predicted next UID\r\nb3 OK [READ-WRITE] SELECT completed\r\n" ++
        // CLOSE expunged it without an EXPUNGE response.
        "b4 OK CLOSE completed\r\n" ++
        "* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)\r\n* OK [PERMANENTFLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)] limited\r\n" ++
        "* 1 EXISTS\r\n* 0 RECENT\r\n* OK [UIDVALIDITY 1234567890] UIDs valid\r\n* OK [UIDNEXT 3] predicted next UID\r\nb5 OK [READ-WRITE] SELECT completed\r\n", transcript[end..]);
}

test "imap session: expunge renumbers from the highest message down" {
    const allocator = std.testing.allocator;
    const transcript = try testSession(allocator, "a1 LOGIN alice@example.com \"pass word\"\r\na2 SELECT INBOX\r\n" ++
        "a3 STORE 1:2 +FLAGS.SILENT (\\Deleted)\r\na4 EXPUNGE\r\na5 FETCH 1:* FLAGS\r\n");
    defer allocator.free(transcript);
    try std.testing.expectStringEndsWith(transcript, "a3 OK STORE completed\r\n* 2 EXPUNGE\r\n* 1 EXPUNGE\r\na4 OK EXPUNGE completed\r\na5 OK FETCH completed\r\n");
}

test "parseDateTime" {
    try std.testing.expectEqual(@as(?u64, 1794044147), parseDateTime(" 7-Nov-2026 09:35:47 +0000"));
    try std.testing.expectEqual(@as(?u64, 1794044147), parseDateTime("07-Nov-2026 10:35:47 +0100"));
    try std.testing.expectEqual(@as(?u64, 951782400), parseDateTime("29-Feb-2000 00:00:00 +0000"));
    try std.testing.expectEqual(@as(?u64, null), parseDateTime("07-Foo-2026 10:35:47 +0100"));
    try std.testing.expectEqual(@as(?u64, null), parseDateTime("07-Nov-2026 10:35:47"));
}

test "imap session: folders, append, copy, move, status" {
    const allocator = std.testing.allocator;
    const transcript = try testSession(allocator, "a1 LOGIN alice@example.com \"pass word\"\r\n" ++
        "a2 CREATE Work/\r\n" ++
        "a3 CREATE Work\r\n" ++
        "a4 CREATE ../evil\r\n" ++
        "a5 APPEND Work (\\Seen) \"29-Feb-2000 00:00:00 +0000\" {7+}\r\nnote\r\n\r\n" ++
        "a6 APPEND Nope {1+}\r\nx\r\n" ++
        "a7 SELECT INBOX\r\n" ++
        "a8 COPY 1 Work\r\n" ++
        "a9 MOVE 2 Trash\r\n" ++
        "b1 STATUS Work (MESSAGES UNSEEN UIDNEXT)\r\n" ++
        "b2 STATUS Trash (MESSAGES)\r\n" ++
        "b3 RENAME Work Archive\r\n" ++
        "b4 SUBSCRIBE Archive\r\n" ++
        "b5 LSUB \"\" \"A*\"\r\n" ++
        "b6 LIST \"\" \"%\"\r\n" ++
        "b7 DELETE Archive\r\n" ++
        "b8 DELETE INBOX\r\n" ++
        "b9 SELECT Trash\r\n");
    defer allocator.free(transcript);
    const end = std.mem.indexOf(u8, transcript, "a1 OK").?;
    const rest = transcript[end..];
    const after_select = std.mem.indexOf(u8, rest, "a7 OK").?;
    try std.testing.expectEqualStrings("a1 OK [CAPABILITY IMAP4rev1 LITERAL+ UNSELECT MOVE SPECIAL-USE] LOGIN completed\r\n" ++
        "a2 OK CREATE completed\r\n" ++
        "a3 NO [ALREADYEXISTS] mailbox exists\r\n" ++
        "a4 NO [CANNOT] invalid mailbox name\r\n" ++
        "a5 OK APPEND completed\r\n" ++
        "a6 NO [TRYCREATE] no such mailbox\r\n", rest[0..std.mem.indexOf(u8, rest, "* FLAGS").?]);
    try std.testing.expectEqualStrings("a7 OK [READ-WRITE] SELECT completed\r\n" ++
        "a8 OK COPY completed\r\n" ++
        "* 2 EXPUNGE\r\na9 OK MOVE completed\r\n" ++
        // The appended note was \Seen; the copy of message 1 was not.
        "* STATUS \"Work\" (MESSAGES 2 UNSEEN 1 UIDNEXT 3)\r\nb1 OK STATUS completed\r\n" ++
        "* STATUS \"Trash\" (MESSAGES 1)\r\nb2 OK STATUS completed\r\n" ++
        "b3 OK RENAME completed\r\n" ++
        "b4 OK SUBSCRIBE completed\r\n" ++
        "* LSUB (\\HasNoChildren) \"/\" \"Archive\"\r\nb5 OK LSUB completed\r\n" ++
        "* LIST (\\HasNoChildren) \"/\" \"INBOX\"\r\n* LIST (\\HasNoChildren) \"/\" \"Archive\"\r\n* LIST (\\HasNoChildren \\Drafts) \"/\" \"Drafts\"\r\n" ++
        "* LIST (\\HasNoChildren \\Junk) \"/\" \"Junk\"\r\n* LIST (\\HasNoChildren \\Sent) \"/\" \"Sent\"\r\n* LIST (\\HasNoChildren \\Trash) \"/\" \"Trash\"\r\nb6 OK LIST completed\r\n" ++
        "b7 OK DELETE completed\r\n" ++
        "b8 NO [CANNOT] INBOX cannot be deleted\r\n", rest[after_select .. std.mem.indexOf(u8, rest, "b8 NO").? + "b8 NO [CANNOT] INBOX cannot be deleted\r\n".len]);
    try std.testing.expect(std.mem.indexOf(u8, rest, "* 1 EXISTS\r\n") != null); // Trash holds the moved message
}

test "imap session: search" {
    const allocator = std.testing.allocator;
    const transcript = try testSession(allocator, "a1 LOGIN alice@example.com \"pass word\"\r\n" ++
        "a2 APPEND INBOX (\\Flagged \\Seen) \"07-Nov-2026 09:35:47 +0000\" {138+}\r\nFrom: Alice <alice@example.com>\r\nTo: bob@example.net\r\nSubject: Quarterly Report\r\nDate: Sat, 07 Nov 2026 09:35:47 +0000\r\n\r\nnumbers inside\r\n\r\n" ++
        "a3 APPEND INBOX (\\Answered) \"02-Nov-2026 12:00:00 +0000\" {90+}\r\nFrom: carol@example.org\r\nSubject: lunch?\r\nDate: Mon, 02 Nov 2026 12:00:00 +0000\r\n\r\npizza\r\n\r\n" ++
        "a4 SELECT INBOX\r\n" ++
        "s01 SEARCH ALL\r\n" ++
        "s02 SEARCH FLAGGED\r\n" ++
        "s03 SEARCH UNSEEN\r\n" ++
        "s04 SEARCH FROM ALICE\r\n" ++
        "s05 SEARCH SUBJECT \"report\"\r\n" ++
        "s06 SEARCH BODY pizza\r\n" ++
        "s07 SEARCH TEXT quarterly\r\n" ++
        "s08 SEARCH SINCE 3-Nov-2026\r\n" ++
        "s09 SEARCH BEFORE \"1-Jan-1971\"\r\n" ++
        "s10 SEARCH SENTON 2-Nov-2026\r\n" ++
        "s11 SEARCH OR FLAGGED ANSWERED\r\n" ++
        "s12 SEARCH NOT SEEN 2:4\r\n" ++
        "s13 SEARCH (OR FROM carol SUBJECT hi) UNANSWERED\r\n" ++
        "s14 SEARCH SMALLER 20\r\n" ++
        "s15 SEARCH RECENT\r\n" ++
        "s16 SEARCH NEW\r\n" ++
        "s17 SEARCH HEADER To bob\r\n" ++
        "s18 UID SEARCH FLAGGED\r\n" ++
        "s19 SEARCH UID 4\r\n" ++
        "s20 SEARCH CHARSET UTF-8 ANSWERED\r\n" ++
        "s21 SEARCH CHARSET KOI8-R ALL\r\n" ++
        "s22 SEARCH BOGUS\r\n");
    defer allocator.free(transcript);
    const start = std.mem.indexOf(u8, transcript, "a4 OK").?;
    try std.testing.expectEqualStrings("a4 OK [READ-WRITE] SELECT completed\r\n" ++
        "* SEARCH 1 2 3 4\r\ns01 OK SEARCH completed\r\n" ++
        "* SEARCH 3\r\ns02 OK SEARCH completed\r\n" ++
        "* SEARCH 1 2 4\r\ns03 OK SEARCH completed\r\n" ++
        "* SEARCH 3\r\ns04 OK SEARCH completed\r\n" ++
        "* SEARCH 3\r\ns05 OK SEARCH completed\r\n" ++
        "* SEARCH 4\r\ns06 OK SEARCH completed\r\n" ++
        "* SEARCH 3\r\ns07 OK SEARCH completed\r\n" ++
        "* SEARCH 3\r\ns08 OK SEARCH completed\r\n" ++
        "* SEARCH 1 2\r\ns09 OK SEARCH completed\r\n" ++
        "* SEARCH 4\r\ns10 OK SEARCH completed\r\n" ++
        "* SEARCH 3 4\r\ns11 OK SEARCH completed\r\n" ++
        "* SEARCH 2 4\r\ns12 OK SEARCH completed\r\n" ++
        "* SEARCH 1\r\ns13 OK SEARCH completed\r\n" ++
        "* SEARCH 2\r\ns14 OK SEARCH completed\r\n" ++
        "* SEARCH 1 2\r\ns15 OK SEARCH completed\r\n" ++
        "* SEARCH 1 2\r\ns16 OK SEARCH completed\r\n" ++
        "* SEARCH 3\r\ns17 OK SEARCH completed\r\n" ++
        "* SEARCH 3\r\ns18 OK SEARCH completed\r\n" ++
        "* SEARCH 4\r\ns19 OK SEARCH completed\r\n" ++
        "* SEARCH 4\r\ns20 OK SEARCH completed\r\n" ++
        "s21 NO [BADCHARSET (US-ASCII UTF-8)] unsupported charset\r\n" ++
        "s22 BAD syntax error\r\n", transcript[start..]);
}

//! Filesystem layout. Mailboxes are standard Maildirs: delivery writes to
//! `tmp/`, syncs, then renames into `new/`; IMAP moves messages to `cur/`
//! and keeps flags in the file name (`<base>:2,<flags>`).
const std = @import("std");
const Io = std.Io;

pub const Storage = struct {
    root_dir: []const u8,

    pub fn init(root_dir: []const u8) Storage {
        return .{ .root_dir = root_dir };
    }

    pub fn ensureLayout(self: Storage, io: Io, allocator: std.mem.Allocator) !void {
        for ([_][]const u8{ "tenants", "queue/outbound" }) |sub| {
            const path = try std.fs.path.join(allocator, &.{ self.root_dir, sub });
            defer allocator.free(path);
            try Io.Dir.cwd().createDirPath(io, path);
        }
    }

    pub fn queuePath(self: Storage, allocator: std.mem.Allocator) ![]u8 {
        return std.fs.path.join(allocator, &.{ self.root_dir, "queue", "outbound" });
    }

    /// Queues a message for remote delivery: `<id>.eml` holds the message,
    /// `<id>.env` the envelope. Both are synced, and the envelope is renamed
    /// into place last, so a listed entry is always complete. Returns the
    /// id; the caller owns it.
    pub fn enqueue(self: Storage, io: Io, allocator: std.mem.Allocator, sender: []const u8, recipients: []const []const u8, header: []const u8, body: []const u8) ![]u8 {
        const queue_path = try self.queuePath(allocator);
        defer allocator.free(queue_path);
        var queue = try Io.Dir.cwd().createDirPathOpen(io, queue_path, .{});
        defer queue.close(io);

        const id = try uniqueName(io, allocator);
        errdefer allocator.free(id);
        var name_buf: [std.fs.max_name_bytes]u8 = undefined;
        var tmp_buf: [std.fs.max_name_bytes]u8 = undefined;

        const message_name = try std.fmt.bufPrint(&name_buf, "{s}.eml", .{id});
        try writeSynced(io, queue, message_name, &.{ header, body });
        errdefer queue.deleteFile(io, message_name) catch {};

        var envelope: Io.Writer.Allocating = .init(allocator);
        defer envelope.deinit();
        const now: u64 = @intCast(@divFloor(Io.Clock.real.now(io).nanoseconds, std.time.ns_per_s));
        try (QueueEntry{ .id = id, .sender = sender, .recipients = recipients, .created = now, .next_attempt = now }).write(&envelope.writer);
        const tmp_name = try std.fmt.bufPrint(&tmp_buf, "{s}.env.tmp", .{id});
        try writeSynced(io, queue, tmp_name, &.{envelope.written()});
        try queue.rename(tmp_name, queue, try std.fmt.bufPrint(&name_buf, "{s}.env", .{id}), io);
        return id;
    }

    pub fn readQueued(self: Storage, io: Io, arena: std.mem.Allocator, id: []const u8) ![]u8 {
        const path = try std.fmt.allocPrint(arena, "{s}/queue/outbound/{s}.eml", .{ self.root_dir, id });
        return Io.Dir.cwd().readFileAlloc(io, path, arena, .unlimited);
    }

    /// Replaces an entry's envelope atomically (remaining recipients, next
    /// attempt).
    pub fn rescheduleQueued(self: Storage, io: Io, allocator: std.mem.Allocator, entry: QueueEntry) !void {
        const queue_path = try self.queuePath(allocator);
        defer allocator.free(queue_path);
        var queue = try Io.Dir.cwd().openDir(io, queue_path, .{});
        defer queue.close(io);
        var envelope: Io.Writer.Allocating = .init(allocator);
        defer envelope.deinit();
        try entry.write(&envelope.writer);
        var tmp_buf: [std.fs.max_name_bytes]u8 = undefined;
        var name_buf: [std.fs.max_name_bytes]u8 = undefined;
        const tmp_name = try std.fmt.bufPrint(&tmp_buf, "{s}.env.tmp", .{entry.id});
        queue.deleteFile(io, tmp_name) catch {};
        try writeSynced(io, queue, tmp_name, &.{envelope.written()});
        try queue.rename(tmp_name, queue, try std.fmt.bufPrint(&name_buf, "{s}.env", .{entry.id}), io);
    }

    /// Removes a finished entry: the envelope first, so a crash in between
    /// leaves only an unlisted message file behind, never a half entry.
    pub fn removeQueued(self: Storage, io: Io, allocator: std.mem.Allocator, id: []const u8) !void {
        for ([_][]const u8{ ".env", ".eml" }) |extension| {
            const path = try std.fmt.allocPrint(allocator, "{s}/queue/outbound/{s}{s}", .{ self.root_dir, id, extension });
            defer allocator.free(path);
            Io.Dir.cwd().deleteFile(io, path) catch |err| switch (err) {
                error.FileNotFound => {},
                else => return err,
            };
        }
    }

    /// Queued entries, oldest first; strings live in `arena`.
    pub fn listQueue(self: Storage, io: Io, arena: std.mem.Allocator) ![]QueueEntry {
        const queue_path = try self.queuePath(arena);
        var queue = Io.Dir.cwd().openDir(io, queue_path, .{ .iterate = true }) catch |err| switch (err) {
            error.FileNotFound => return &.{},
            else => return err,
        };
        defer queue.close(io);
        var entries = std.ArrayList(QueueEntry).empty;
        var it = queue.iterate();
        while (try it.next(io)) |entry| {
            if (entry.kind != .file or !std.mem.endsWith(u8, entry.name, ".env")) continue;
            const id = entry.name[0 .. entry.name.len - ".env".len];
            const raw = try queue.readFileAlloc(io, entry.name, arena, .limited(1024 * 1024));
            const parsed = QueueEntry.parse(arena, try arena.dupe(u8, id), raw) catch {
                std.log.scoped(.storage).warn("skipping unreadable queue envelope {s}", .{entry.name});
                continue;
            };
            try entries.append(arena, parsed);
        }
        std.sort.pdq(QueueEntry, entries.items, {}, struct {
            fn lessThan(_: void, a: QueueEntry, b: QueueEntry) bool {
                return std.mem.order(u8, a.id, b.id) == .lt;
            }
        }.lessThan);
        return entries.items;
    }

    pub fn tenantIndexPath(self: Storage, allocator: std.mem.Allocator) ![]u8 {
        return std.fs.path.join(allocator, &.{ self.root_dir, "tenants", "index.txt" });
    }

    pub fn aliasIndexPath(self: Storage, allocator: std.mem.Allocator, tenant: []const u8, domain: []const u8) ![]u8 {
        return std.fs.path.join(allocator, &.{ self.root_dir, "tenants", tenant, "domains", domain, "aliases.txt" });
    }

    pub fn accountIndexPath(self: Storage, allocator: std.mem.Allocator, tenant: []const u8, domain: []const u8) ![]u8 {
        return std.fs.path.join(allocator, &.{ self.root_dir, "tenants", tenant, "domains", domain, "accounts.txt" });
    }

    pub fn dkimPath(self: Storage, allocator: std.mem.Allocator, tenant: []const u8, domain: []const u8) ![]u8 {
        return std.fs.path.join(allocator, &.{ self.root_dir, "tenants", tenant, "domains", domain, "dkim" });
    }

    pub fn maildirPath(self: Storage, allocator: std.mem.Allocator, tenant: []const u8, domain: []const u8, user: []const u8) ![]u8 {
        return std.fs.path.join(allocator, &.{ self.root_dir, "tenants", tenant, "domains", domain, "users", user, "Maildir" });
    }

    /// Delivers `header` followed by `body` to the user's INBOX. The message
    /// is durable once this returns. Returns the new file name; the caller
    /// owns it.
    pub fn deliver(self: Storage, io: Io, allocator: std.mem.Allocator, tenant: []const u8, domain: []const u8, user: []const u8, header: []const u8, body: []const u8) ![]u8 {
        const maildir_path = try self.maildirPath(allocator, tenant, domain, user);
        defer allocator.free(maildir_path);
        return deliverTo(io, allocator, maildir_path, header, body, .{});
    }

    /// Opens a Maildir for IMAP: moves `new/` mail to `cur/`, assigns UIDs to
    /// messages seen for the first time, and returns everything in UID order.
    pub fn openMailbox(io: Io, allocator: std.mem.Allocator, maildir_path: []const u8) !Mailbox {
        var maildir = try Io.Dir.cwd().createDirPathOpen(io, maildir_path, .{});
        defer maildir.close(io);
        for ([_][]const u8{ "tmp", "new", "cur" }) |sub| try maildir.createDirPath(io, sub);

        // Concurrent sessions must not hand out the same UID twice.
        const lock = try maildir.createFile(io, "raven-uidlist.lock", .{ .truncate = false });
        defer lock.close(io);
        try lock.lock(io, .exclusive);
        defer lock.unlock(io);

        var arena_state = std.heap.ArenaAllocator.init(allocator);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        const claimed = try claimNew(io, arena, maildir);
        var uids = try UidList.load(io, arena, maildir);

        var messages = std.ArrayList(Message).empty;
        defer messages.deinit(allocator);
        errdefer for (messages.items) |message| allocator.free(message.path);

        var cur = try maildir.openDir(io, "cur", .{ .iterate = true });
        defer cur.close(io);
        var it = cur.iterate();
        while (try it.next(io)) |entry| {
            if (entry.kind != .file) continue;
            const stat = try cur.statFile(io, entry.name, .{});
            const path = try std.fs.path.join(allocator, &.{ maildir_path, "cur", entry.name });
            errdefer allocator.free(path);
            // INTERNALDATE is the file's mtime, as in Dovecot, so imported
            // Maildirs keep their dates.
            const seconds: u64 = @intCast(@max(0, @divFloor(stat.mtime.nanoseconds, std.time.ns_per_s)));
            try messages.append(allocator, .{ .path = path, .size = stat.size, .flags = .fromFileName(entry.name), .uid = 0, .internal_date = seconds });
        }

        // New mail gets UIDs in delivery order; names sort that way.
        std.sort.pdq(Message, messages.items, {}, olderFirst);
        var changed = false;
        var known: usize = 0;
        for (messages.items) |*message| {
            for (claimed) |name| message.recent = message.recent or std.mem.eql(u8, name, baseName(message.path));
            if (uids.map.get(baseName(message.path))) |uid| {
                message.uid = uid;
                known += 1;
            } else {
                message.uid = uids.next;
                uids.next += 1;
                changed = true;
            }
        }
        // Entries for expunged messages are dropped; their UIDs are never reused.
        if (known != uids.map.count()) changed = true;
        std.sort.pdq(Message, messages.items, {}, lowerUid);
        if (changed) try uids.save(io, maildir, messages.items);

        return .{ .messages = try messages.toOwnedSlice(allocator), .uid_validity = uids.validity, .uid_next = uids.next };
    }

    pub fn readMessage(io: Io, allocator: std.mem.Allocator, message: Message) ![]u8 {
        // No cap of its own: SMTP's max_message_size bounds what gets stored.
        return Io.Dir.cwd().readFileAlloc(io, message.path, allocator, .unlimited);
    }

    /// Renames the message so its file name carries `flags`.
    pub fn setFlags(io: Io, allocator: std.mem.Allocator, message: *Message, flags: MessageFlags) !void {
        if (std.meta.eql(flags, message.flags)) return;
        var letters_buf: [5]u8 = undefined;
        var name_buf: [std.fs.max_name_bytes]u8 = undefined;
        const name = try std.fmt.bufPrint(&name_buf, "{s}:2,{s}", .{ baseName(message.path), flags.letters(&letters_buf) });
        const path = try std.fs.path.join(allocator, &.{ std.fs.path.dirname(message.path).?, name });
        errdefer allocator.free(path);

        try Io.Dir.cwd().rename(message.path, Io.Dir.cwd(), path, io);
        allocator.free(message.path);
        message.path = path;
        message.flags = flags;
    }

    pub fn deleteMessage(io: Io, message: Message) !void {
        Io.Dir.cwd().deleteFile(io, message.path) catch |err| switch (err) {
            error.FileNotFound => {},
            else => return err,
        };
    }
};

pub const Message = struct {
    /// Current path of the file in `cur/`; changes when flags change.
    path: []u8,
    size: u64,
    flags: MessageFlags,
    uid: u32,
    /// Arrival time in Unix seconds (IMAP INTERNALDATE), from the mtime.
    internal_date: u64 = 0,
    /// Moved out of `new/` by this open: IMAP's session-only \Recent.
    recent: bool = false,
};

pub const Mailbox = struct {
    /// Ascending UIDs, so position + 1 is the IMAP sequence number.
    messages: []Message,
    uid_validity: u32,
    uid_next: u32,
};

/// `raven-uidlist` in each Maildir: `<uidvalidity> <uidnext>` on the first
/// line, then `<uid> <base name>` per message.
const UidList = struct {
    validity: u32,
    next: u32,
    /// Base name -> UID; keys point into the loaded file.
    map: std.StringHashMapUnmanaged(u32) = .empty,

    fn load(io: Io, arena: std.mem.Allocator, maildir: Io.Dir) !UidList {
        const fresh: UidList = .{ .validity = @intCast(@divFloor(Io.Clock.real.now(io).nanoseconds, std.time.ns_per_s)), .next = 1 };
        const raw = maildir.readFileAlloc(io, "raven-uidlist", arena, .limited(64 * 1024 * 1024)) catch |err| switch (err) {
            error.FileNotFound => return fresh,
            else => return err,
        };
        // A damaged list starts over with a new UIDVALIDITY, which tells
        // clients to drop their caches instead of trusting wrong UIDs.
        return parse(arena, raw) catch fresh;
    }

    fn parse(arena: std.mem.Allocator, raw: []const u8) !UidList {
        var lines = std.mem.tokenizeScalar(u8, raw, '\n');
        var header = std.mem.tokenizeScalar(u8, lines.next() orelse return error.Corrupt, ' ');
        var list: UidList = .{
            .validity = try std.fmt.parseInt(u32, header.next() orelse return error.Corrupt, 10),
            .next = try std.fmt.parseInt(u32, header.next() orelse return error.Corrupt, 10),
        };
        while (lines.next()) |line| {
            const space = std.mem.indexOfScalar(u8, line, ' ') orelse return error.Corrupt;
            const uid = try std.fmt.parseInt(u32, line[0..space], 10);
            if (uid == 0 or uid >= list.next) return error.Corrupt;
            try list.map.put(arena, line[space + 1 ..], uid);
        }
        return list;
    }

    /// Written to a temporary file and renamed, so a crash never leaves a
    /// half-written list behind.
    fn save(self: UidList, io: Io, maildir: Io.Dir, messages: []const Message) !void {
        {
            const file = try maildir.createFile(io, "raven-uidlist.tmp", .{});
            defer file.close(io);
            var buf: [4096]u8 = undefined;
            var writer = file.writerStreaming(io, &buf);
            try writer.interface.print("{d} {d}\n", .{ self.validity, self.next });
            for (messages) |message| try writer.interface.print("{d} {s}\n", .{ message.uid, baseName(message.path) });
            try writer.interface.flush();
            try file.sync(io);
        }
        try maildir.rename("raven-uidlist.tmp", maildir, "raven-uidlist", io);
    }
};

pub fn freeMessages(allocator: std.mem.Allocator, messages: []Message) void {
    for (messages) |message| allocator.free(message.path);
    allocator.free(messages);
}

pub const MessageFlags = struct {
    seen: bool = false,
    answered: bool = false,
    flagged: bool = false,
    deleted: bool = false,
    draft: bool = false,

    /// Reads the Maildir info suffix: `<base>:2,<letters>`.
    pub fn fromFileName(name: []const u8) MessageFlags {
        const info = std.mem.indexOf(u8, name, ":2,") orelse return .{};
        var flags: MessageFlags = .{};
        for (name[info + 3 ..]) |ch| switch (ch) {
            'D' => flags.draft = true,
            'F' => flags.flagged = true,
            'R' => flags.answered = true,
            'S' => flags.seen = true,
            'T' => flags.deleted = true,
            else => {},
        };
        return flags;
    }

    /// Maildir info letters, in the ASCII order the format requires.
    fn letters(self: MessageFlags, buf: *[5]u8) []const u8 {
        var n: usize = 0;
        for ([_]struct { bool, u8 }{ .{ self.draft, 'D' }, .{ self.flagged, 'F' }, .{ self.answered, 'R' }, .{ self.seen, 'S' }, .{ self.deleted, 'T' } }) |flag| {
            if (!flag[0]) continue;
            buf[n] = flag[1];
            n += 1;
        }
        return buf[0..n];
    }

    pub fn without(self: MessageFlags, other: MessageFlags) MessageFlags {
        return .{
            .seen = self.seen and !other.seen,
            .answered = self.answered and !other.answered,
            .flagged = self.flagged and !other.flagged,
            .deleted = self.deleted and !other.deleted,
            .draft = self.draft and !other.draft,
        };
    }

    pub fn merge(self: MessageFlags, other: MessageFlags) MessageFlags {
        return .{
            .seen = self.seen or other.seen,
            .answered = self.answered or other.answered,
            .flagged = self.flagged or other.flagged,
            .deleted = self.deleted or other.deleted,
            .draft = self.draft or other.draft,
        };
    }
};

/// The Maildir of `folder`, where INBOX is the user's top-level Maildir
/// and `Work/Projects` lives in `.Work.Projects` (Maildir++).
pub fn folderPath(allocator: std.mem.Allocator, maildir_path: []const u8, folder: []const u8) ![]u8 {
    if (std.ascii.eqlIgnoreCase(folder, "INBOX")) return allocator.dupe(u8, maildir_path);
    std.debug.assert(isFolderName(folder));
    const dir = try std.mem.concat(allocator, u8, &.{ ".", folder });
    defer allocator.free(dir);
    std.mem.replaceScalar(u8, dir, '/', '.');
    return std.fs.path.join(allocator, &.{ maildir_path, dir });
}

/// An outbound queue envelope. The text form is one `key value` per line.
pub const QueueEntry = struct {
    id: []const u8,
    /// Reverse-path without brackets; empty for bounces.
    sender: []const u8,
    recipients: []const []const u8,
    /// Unix seconds.
    created: u64,
    next_attempt: u64,
    attempts: u32 = 0,

    pub fn write(self: QueueEntry, w: *Io.Writer) !void {
        try w.print("sender {s}\ncreated {d}\nnext {d}\nattempts {d}\n", .{ self.sender, self.created, self.next_attempt, self.attempts });
        for (self.recipients) |recipient| try w.print("recipient {s}\n", .{recipient});
    }

    fn parse(arena: std.mem.Allocator, id: []const u8, raw: []const u8) !QueueEntry {
        var entry: QueueEntry = .{ .id = id, .sender = "", .recipients = &.{}, .created = 0, .next_attempt = 0 };
        var recipients = std.ArrayList([]const u8).empty;
        var saw_sender = false;
        var lines = std.mem.tokenizeScalar(u8, raw, '\n');
        while (lines.next()) |line| {
            const space = std.mem.indexOfScalar(u8, line, ' ') orelse line.len;
            const key = line[0..space];
            const value = if (space < line.len) line[space + 1 ..] else "";
            if (std.mem.eql(u8, key, "sender")) {
                entry.sender = value;
                saw_sender = true;
            } else if (std.mem.eql(u8, key, "created")) {
                entry.created = try std.fmt.parseInt(u64, value, 10);
            } else if (std.mem.eql(u8, key, "next")) {
                entry.next_attempt = try std.fmt.parseInt(u64, value, 10);
            } else if (std.mem.eql(u8, key, "attempts")) {
                entry.attempts = try std.fmt.parseInt(u32, value, 10);
            } else if (std.mem.eql(u8, key, "recipient")) {
                try recipients.append(arena, value);
            } else return error.Corrupt;
        }
        if (!saw_sender or recipients.items.len == 0) return error.Corrupt;
        entry.recipients = recipients.items;
        return entry;
    }
};

/// Writes `parts` to a new file `name` in `dir` and syncs it.
fn writeSynced(io: Io, dir: Io.Dir, name: []const u8, parts: []const []const u8) !void {
    const file = try dir.createFile(io, name, .{ .exclusive = true });
    defer file.close(io);
    for (parts) |part| try file.writeStreamingAll(io, part);
    try file.sync(io);
}

pub const DeliverOptions = struct {
    /// Given flags put the message straight into `cur/` (APPEND, COPY).
    flags: ?MessageFlags = null,
    /// Arrival time to record instead of now (APPEND date, COPY), stored as
    /// the file's mtime like Dovecot does.
    date: ?u64 = null,
};

/// Writes a message into the Maildir at `maildir_path` (tmp, sync, rename).
/// Returns the file name; the caller owns it.
pub fn deliverTo(io: Io, allocator: std.mem.Allocator, maildir_path: []const u8, header: []const u8, body: []const u8, options: DeliverOptions) ![]u8 {
    var maildir = try Io.Dir.cwd().createDirPathOpen(io, maildir_path, .{});
    defer maildir.close(io);
    for ([_][]const u8{ "tmp", "new", "cur" }) |sub| try maildir.createDirPath(io, sub);

    const unique = try uniqueName(io, allocator);
    defer allocator.free(unique);
    var letters_buf: [5]u8 = undefined;
    const name = if (options.flags) |flags| try std.fmt.allocPrint(allocator, "{s}:2,{s}", .{ unique, flags.letters(&letters_buf) }) else try allocator.dupe(u8, unique);
    errdefer allocator.free(name);
    var tmp_buf: [std.fs.max_name_bytes + 4]u8 = undefined;
    var final_buf: [std.fs.max_name_bytes + 4]u8 = undefined;
    const tmp_path = try std.fmt.bufPrint(&tmp_buf, "tmp/{s}", .{unique});
    const final_path = try std.fmt.bufPrint(&final_buf, "{s}/{s}", .{ if (options.flags != null) "cur" else "new", name });

    const file = try maildir.createFile(io, tmp_path, .{ .exclusive = true });
    errdefer maildir.deleteFile(io, tmp_path) catch {};
    {
        defer file.close(io);
        try file.writeStreamingAll(io, header);
        try file.writeStreamingAll(io, body);
        if (options.date) |seconds| try file.setTimestamps(io, .{ .modify_timestamp = .{ .new = .{ .nanoseconds = @as(i96, seconds) * std.time.ns_per_s } } });
        try file.sync(io);
    }
    try maildir.rename(tmp_path, maildir, final_path, io);
    return name;
}

/// Folder names map to directory names, so they get an allow-list: `/`
/// separates levels; `.` (the Maildir++ separator), wildcards, quotes,
/// backslashes and control characters are refused.
pub fn isFolderName(name: []const u8) bool {
    if (name.len == 0 or name.len > 200) return false;
    var levels = std.mem.splitScalar(u8, name, '/');
    while (levels.next()) |level| {
        if (level.len == 0) return false;
        for (level) |ch| {
            if (ch < 0x20 or ch > 0x7e or std.mem.indexOfScalar(u8, ".%*\"\\", ch) != null) return false;
        }
    }
    return true;
}

/// Folder names under `maildir_path` (not INBOX), `/`-separated.
pub fn listFolders(io: Io, arena: std.mem.Allocator, maildir_path: []const u8) ![]const []const u8 {
    var maildir = Io.Dir.cwd().openDir(io, maildir_path, .{ .iterate = true }) catch |err| switch (err) {
        error.FileNotFound => return &.{},
        else => return err,
    };
    defer maildir.close(io);
    var names = std.ArrayList([]const u8).empty;
    var it = maildir.iterate();
    while (try it.next(io)) |entry| {
        if (entry.kind != .directory or entry.name.len < 2 or entry.name[0] != '.') continue;
        const name = try arena.dupe(u8, entry.name[1..]);
        std.mem.replaceScalar(u8, name, '.', '/');
        if (isFolderName(name)) try names.append(arena, name);
    }
    std.sort.pdq([]const u8, names.items, {}, lessThanString);
    return names.items;
}

pub fn createFolder(io: Io, allocator: std.mem.Allocator, maildir_path: []const u8, folder: []const u8) !void {
    const path = try folderPath(allocator, maildir_path, folder);
    defer allocator.free(path);
    Io.Dir.cwd().createDir(io, path, .default_dir) catch |err| switch (err) {
        error.PathAlreadyExists => return error.FolderExists,
        error.FileNotFound => {
            try Io.Dir.cwd().createDirPath(io, maildir_path);
            try Io.Dir.cwd().createDir(io, path, .default_dir);
        },
        else => return err,
    };
    var dir = try Io.Dir.cwd().openDir(io, path, .{});
    defer dir.close(io);
    for ([_][]const u8{ "tmp", "new", "cur" }) |sub| try dir.createDirPath(io, sub);
}

pub fn deleteFolder(io: Io, allocator: std.mem.Allocator, maildir_path: []const u8, folder: []const u8) !void {
    const path = try folderPath(allocator, maildir_path, folder);
    defer allocator.free(path);
    Io.Dir.cwd().access(io, path, .{}) catch return error.NoSuchFolder;
    try Io.Dir.cwd().deleteTree(io, path);
}

/// Renames `from` and every folder below it.
pub fn renameFolder(io: Io, allocator: std.mem.Allocator, maildir_path: []const u8, from: []const u8, to: []const u8) !void {
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const folders = try listFolders(io, arena, maildir_path);
    var found = false;
    for (folders) |folder| {
        if (std.mem.eql(u8, folder, to)) return error.FolderExists;
        found = found or std.mem.eql(u8, folder, from);
    }
    if (!found) return error.NoSuchFolder;
    for (folders) |folder| {
        const below = std.mem.startsWith(u8, folder, from) and folder.len > from.len and folder[from.len] == '/';
        if (!std.mem.eql(u8, folder, from) and !below) continue;
        const renamed = try std.mem.concat(arena, u8, &.{ to, folder[from.len..] });
        if (!isFolderName(renamed)) return error.InvalidFolderName;
        try Io.Dir.cwd().rename(try folderPath(arena, maildir_path, folder), Io.Dir.cwd(), try folderPath(arena, maildir_path, renamed), io);
    }
}

/// Subscribed folder names, one per line in `subscriptions`.
pub fn readSubscriptions(io: Io, arena: std.mem.Allocator, maildir_path: []const u8) ![]const []const u8 {
    const path = try std.fs.path.join(arena, &.{ maildir_path, "subscriptions" });
    const raw = Io.Dir.cwd().readFileAlloc(io, path, arena, .limited(1024 * 1024)) catch |err| switch (err) {
        error.FileNotFound => return &.{},
        else => return err,
    };
    var names = std.ArrayList([]const u8).empty;
    var lines = std.mem.tokenizeScalar(u8, raw, '\n');
    while (lines.next()) |line| {
        const name = std.mem.trimEnd(u8, line, "\r");
        if (isFolderName(name) or std.ascii.eqlIgnoreCase(name, "INBOX")) try names.append(arena, name);
    }
    return names.items;
}

pub fn writeSubscriptions(io: Io, allocator: std.mem.Allocator, maildir_path: []const u8, names: []const []const u8) !void {
    try Io.Dir.cwd().createDirPath(io, maildir_path);
    var text: Io.Writer.Allocating = .init(allocator);
    defer text.deinit();
    for (names) |name| try text.writer.print("{s}\n", .{name});
    const tmp = try std.fs.path.join(allocator, &.{ maildir_path, "subscriptions.tmp" });
    defer allocator.free(tmp);
    const path = try std.fs.path.join(allocator, &.{ maildir_path, "subscriptions" });
    defer allocator.free(path);
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = tmp, .data = text.written() });
    try Io.Dir.cwd().rename(tmp, Io.Dir.cwd(), path, io);
}

fn lessThanString(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.order(u8, a, b) == .lt;
}

/// `<seconds>.M<microseconds>R<random>.raven`: unique across processes and
/// restarts, and sorts in delivery order.
fn uniqueName(io: Io, allocator: std.mem.Allocator) ![]u8 {
    // Unsigned on purpose: a signed value formatted with a width gets a '+'.
    const ns: u96 = @intCast(Io.Clock.real.now(io).nanoseconds);
    var random: [8]u8 = undefined;
    io.random(&random);
    return std.fmt.allocPrint(allocator, "{d}.M{d:0>6}R{x:0>16}.raven", .{
        ns / std.time.ns_per_s,
        ns / std.time.ns_per_us % std.time.us_per_s,
        std.mem.readInt(u64, &random, .little),
    });
}

/// Moves everything in `new/` to `cur/` and returns the names it moved.
fn claimNew(io: Io, arena: std.mem.Allocator, maildir: Io.Dir) ![]const []const u8 {
    var new = maildir.openDir(io, "new", .{ .iterate = true }) catch |err| switch (err) {
        error.FileNotFound => return &.{},
        else => return err,
    };
    defer new.close(io);

    // Collect first: renaming entries out of a directory while iterating it is unspecified.
    var names = std.ArrayList([]const u8).empty;
    var it = new.iterate();
    while (try it.next(io)) |entry| {
        if (entry.kind == .file) try names.append(arena, try arena.dupe(u8, entry.name));
    }
    var claimed = std.ArrayList([]const u8).empty;

    var from_buf: [std.fs.max_name_bytes + 4]u8 = undefined;
    var to_buf: [std.fs.max_name_bytes + 8]u8 = undefined;
    for (names.items) |name| {
        const from = try std.fmt.bufPrint(&from_buf, "new/{s}", .{name});
        const to = try std.fmt.bufPrint(&to_buf, "cur/{s}:2,", .{name});
        maildir.rename(from, maildir, to, io) catch |err| switch (err) {
            error.FileNotFound => continue, // claimed by a concurrent session
            else => return err,
        };
        try claimed.append(arena, name);
    }
    return claimed.items;
}

fn baseName(path: []const u8) []const u8 {
    const name = std.fs.path.basename(path);
    return name[0 .. std.mem.indexOf(u8, name, ":2,") orelse name.len];
}

fn olderFirst(_: void, a: Message, b: Message) bool {
    return std.mem.order(u8, baseName(a.path), baseName(b.path)) == .lt;
}

fn lowerUid(_: void, a: Message, b: Message) bool {
    return a.uid < b.uid;
}

fn testInbox(allocator: std.mem.Allocator, root: []const u8) ![]u8 {
    return Storage.init(root).maildirPath(allocator, "acme", "example.com", "alice");
}

fn testRoot(allocator: std.mem.Allocator, tmp: *std.testing.TmpDir) ![]u8 {
    return std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", tmp.sub_path[0..] });
}

test "deliver goes through tmp into new and survives a fresh Storage" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try testRoot(allocator, &tmp);
    defer allocator.free(root);

    // Separate instances stand in for a restart: names must not collide.
    for (0..3) |_| allocator.free(try Storage.init(root).deliver(io, allocator, "acme", "example.com", "alice", "", "hello\r\n"));

    var new = try tmp.dir.openDir(io, "tenants/acme/domains/example.com/users/alice/Maildir/new", .{ .iterate = true });
    defer new.close(io);
    var count: usize = 0;
    var it = new.iterate();
    while (try it.next(io)) |_| count += 1;
    try std.testing.expectEqual(@as(usize, 3), count);

    var tmp_dir = try tmp.dir.openDir(io, "tenants/acme/domains/example.com/users/alice/Maildir/tmp", .{ .iterate = true });
    defer tmp_dir.close(io);
    var tmp_it = tmp_dir.iterate();
    try std.testing.expect(try tmp_it.next(io) == null);
}

test "opening claims new mail into cur, oldest first" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try testRoot(allocator, &tmp);
    defer allocator.free(root);
    const inbox = try testInbox(allocator, root);
    defer allocator.free(inbox);
    const storage = Storage.init(root);

    for ([_][]const u8{ "one", "two", "three" }) |body| allocator.free(try storage.deliver(io, allocator, "acme", "example.com", "alice", "", body));

    const mailbox = try Storage.openMailbox(io, allocator, inbox);
    defer freeMessages(allocator, mailbox.messages);
    try std.testing.expectEqual(@as(usize, 3), mailbox.messages.len);
    for (mailbox.messages, [_][]const u8{ "one", "two", "three" }, 1..) |message, expected, uid| {
        try std.testing.expectEqual(@as(u32, @intCast(uid)), message.uid);
        try std.testing.expect(std.mem.indexOf(u8, message.path, "/cur/") != null);
        const body = try Storage.readMessage(io, allocator, message);
        defer allocator.free(body);
        try std.testing.expectEqualStrings(expected, body);
    }
    try std.testing.expectEqual(@as(u32, 4), mailbox.uid_next);
}

test "UIDs survive restarts and expunges and are never reused" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try testRoot(allocator, &tmp);
    defer allocator.free(root);
    const inbox = try testInbox(allocator, root);
    defer allocator.free(inbox);

    for (0..3) |_| allocator.free(try Storage.init(root).deliver(io, allocator, "acme", "example.com", "alice", "", "x"));
    const first = try Storage.openMailbox(io, allocator, inbox);
    defer freeMessages(allocator, first.messages);
    try Storage.deleteMessage(io, first.messages[1]); // UID 2

    // A fresh Storage stands in for a restart.
    allocator.free(try Storage.init(root).deliver(io, allocator, "acme", "example.com", "alice", "", "y"));
    const second = try Storage.openMailbox(io, allocator, inbox);
    defer freeMessages(allocator, second.messages);
    try std.testing.expectEqual(first.uid_validity, second.uid_validity);
    try std.testing.expectEqual(@as(usize, 3), second.messages.len);
    for (second.messages, [_]u32{ 1, 3, 4 }) |message, uid| try std.testing.expectEqual(uid, message.uid);
    try std.testing.expectEqual(@as(u32, 5), second.uid_next);
}

test "a damaged UID list resets UIDVALIDITY" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try testRoot(allocator, &tmp);
    defer allocator.free(root);
    const inbox = try testInbox(allocator, root);
    defer allocator.free(inbox);
    const storage = Storage.init(root);

    allocator.free(try storage.deliver(io, allocator, "acme", "example.com", "alice", "", "x"));
    try tmp.dir.writeFile(io, .{ .sub_path = "tenants/acme/domains/example.com/users/alice/Maildir/raven-uidlist", .data = "7 3\n9 bogus\n" });
    const mailbox = try Storage.openMailbox(io, allocator, inbox);
    defer freeMessages(allocator, mailbox.messages);
    try std.testing.expect(mailbox.uid_validity != 7);
    try std.testing.expectEqual(@as(u32, 1), mailbox.messages[0].uid);
}

test "flags live in the file name and survive reopening" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try testRoot(allocator, &tmp);
    defer allocator.free(root);
    const inbox = try testInbox(allocator, root);
    defer allocator.free(inbox);
    const storage = Storage.init(root);

    allocator.free(try storage.deliver(io, allocator, "acme", "example.com", "alice", "Subject: x\r\n", "hello"));
    {
        const mailbox = try Storage.openMailbox(io, allocator, inbox);
        defer freeMessages(allocator, mailbox.messages);
        try Storage.setFlags(io, allocator, &mailbox.messages[0], .{ .seen = true, .flagged = true, .deleted = true });
        try std.testing.expect(std.mem.endsWith(u8, mailbox.messages[0].path, ":2,FST"));
    }

    const mailbox = try Storage.openMailbox(io, allocator, inbox);
    defer freeMessages(allocator, mailbox.messages);
    try std.testing.expectEqual(MessageFlags{ .seen = true, .flagged = true, .deleted = true }, mailbox.messages[0].flags);
    try std.testing.expectEqual(@as(u32, 1), mailbox.messages[0].uid); // renames keep the UID

    try Storage.deleteMessage(io, mailbox.messages[0]);
    const after = try Storage.openMailbox(io, allocator, inbox);
    defer freeMessages(allocator, after.messages);
    try std.testing.expectEqual(@as(usize, 0), after.messages.len);
}

test "unique names are well formed" {
    const name = try uniqueName(std.testing.io, std.testing.allocator);
    defer std.testing.allocator.free(name);
    try std.testing.expect(std.mem.indexOfAny(u8, name, "+-/: ") == null);
    try std.testing.expect(std.mem.endsWith(u8, name, ".raven"));
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, name, ".M"));
}

test "maildir flags parse and format" {
    try std.testing.expectEqual(MessageFlags{ .draft = true, .answered = true, .seen = true }, MessageFlags.fromFileName("1.M1R1.raven:2,DRS"));
    try std.testing.expectEqual(MessageFlags{}, MessageFlags.fromFileName("1.M1R1.raven"));
    var buf: [5]u8 = undefined;
    try std.testing.expectEqualStrings("DFRST", (MessageFlags{ .seen = true, .answered = true, .flagged = true, .deleted = true, .draft = true }).letters(&buf));
}

test "account index path is stable" {
    const allocator = std.testing.allocator;
    const path = try Storage.init("data").accountIndexPath(allocator, "tenant-a", "example.com");
    defer allocator.free(path);
    try std.testing.expectEqualStrings("data/tenants/tenant-a/domains/example.com/accounts.txt", path);
}

test "folder names are allow-listed" {
    for ([_][]const u8{ "Sent", "Work/Projects", "Caf&AOk-", "a-b_c d" }) |name| try std.testing.expect(isFolderName(name));
    for ([_][]const u8{ "", ".hidden", "a.b", "../x", "a//b", "/a", "a/", "*", "a%b", "a\\b", "a\"b", "a\x00b" }) |name| try std.testing.expect(!isFolderName(name));
}

test "folders: create, list, rename with children, delete, subscribe" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try testRoot(allocator, &tmp);
    defer allocator.free(root);
    const inbox = try testInbox(allocator, root);
    defer allocator.free(inbox);
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    try createFolder(io, allocator, inbox, "Work");
    try createFolder(io, allocator, inbox, "Work/Projects");
    try createFolder(io, allocator, inbox, "Sent");
    try std.testing.expectError(error.FolderExists, createFolder(io, allocator, inbox, "Sent"));
    try tmp.dir.access(io, "tenants/acme/domains/example.com/users/alice/Maildir/.Work.Projects/cur", .{});

    try renameFolder(io, allocator, inbox, "Work", "Archive");
    try std.testing.expectError(error.NoSuchFolder, renameFolder(io, allocator, inbox, "Work", "Other"));
    try std.testing.expectError(error.FolderExists, renameFolder(io, allocator, inbox, "Archive", "Sent"));
    const folders = try listFolders(io, arena, inbox);
    try std.testing.expectEqual(@as(usize, 3), folders.len);
    try std.testing.expectEqualStrings("Archive", folders[0]);
    try std.testing.expectEqualStrings("Archive/Projects", folders[1]);
    try std.testing.expectEqualStrings("Sent", folders[2]);

    try deleteFolder(io, allocator, inbox, "Archive/Projects");
    try std.testing.expectError(error.NoSuchFolder, deleteFolder(io, allocator, inbox, "Archive/Projects"));

    try writeSubscriptions(io, allocator, inbox, &.{ "INBOX", "Sent" });
    const subscribed = try readSubscriptions(io, arena, inbox);
    try std.testing.expectEqual(@as(usize, 2), subscribed.len);
    try std.testing.expectEqualStrings("Sent", subscribed[1]);
}

test "deliverTo with flags and a date lands in cur" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try testRoot(allocator, &tmp);
    defer allocator.free(root);
    const inbox = try testInbox(allocator, root);
    defer allocator.free(inbox);

    const sent = try folderPath(allocator, inbox, "Sent");
    defer allocator.free(sent);
    allocator.free(try deliverTo(io, allocator, sent, "", "draft", .{ .flags = .{ .seen = true }, .date = 951782400 }));
    const mailbox = try Storage.openMailbox(io, allocator, sent);
    defer freeMessages(allocator, mailbox.messages);
    try std.testing.expectEqual(@as(usize, 1), mailbox.messages.len);
    try std.testing.expect(mailbox.messages[0].flags.seen);
    try std.testing.expect(!mailbox.messages[0].recent); // went straight to cur/
    try std.testing.expectEqual(@as(u64, 951782400), mailbox.messages[0].internal_date);
}

test "queue entries are durable and survive a restart" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try testRoot(allocator, &tmp);
    defer allocator.free(root);

    allocator.free(try Storage.init(root).enqueue(io, allocator, "alice@example.com", &.{ "bob@remote.test", "carol@other.test" }, "Received: x\r\n", "hi\r\n"));
    allocator.free(try Storage.init(root).enqueue(io, allocator, "", &.{"dan@remote.test"}, "", "bounce\r\n"));

    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const entries = try Storage.init(root).listQueue(io, arena_state.allocator());
    try std.testing.expectEqual(@as(usize, 2), entries.len);
    try std.testing.expectEqualStrings("alice@example.com", entries[0].sender);
    try std.testing.expectEqual(@as(usize, 2), entries[0].recipients.len);
    try std.testing.expectEqualStrings("carol@other.test", entries[0].recipients[1]);
    try std.testing.expectEqualStrings("", entries[1].sender);

    const message = try std.fmt.allocPrint(allocator, "queue/outbound/{s}.eml", .{entries[0].id});
    defer allocator.free(message);
    const data = try tmp.dir.readFileAlloc(io, message, allocator, .limited(1024));
    defer allocator.free(data);
    try std.testing.expectEqualStrings("Received: x\r\nhi\r\n", data);
}

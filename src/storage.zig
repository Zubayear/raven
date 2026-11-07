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
        const tenants = try std.fs.path.join(allocator, &.{ self.root_dir, "tenants" });
        defer allocator.free(tenants);
        try Io.Dir.cwd().createDirPath(io, tenants);
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

    pub fn maildirPath(self: Storage, allocator: std.mem.Allocator, tenant: []const u8, domain: []const u8, user: []const u8) ![]u8 {
        return std.fs.path.join(allocator, &.{ self.root_dir, "tenants", tenant, "domains", domain, "users", user, "Maildir" });
    }

    /// Delivers `header` followed by `body` to the user's Maildir. The message
    /// is durable once this returns. Returns the new file name; the caller
    /// owns it.
    pub fn deliver(self: Storage, io: Io, allocator: std.mem.Allocator, tenant: []const u8, domain: []const u8, user: []const u8, header: []const u8, body: []const u8) ![]u8 {
        const maildir_path = try self.maildirPath(allocator, tenant, domain, user);
        defer allocator.free(maildir_path);
        var maildir = try Io.Dir.cwd().createDirPathOpen(io, maildir_path, .{});
        defer maildir.close(io);
        for ([_][]const u8{ "tmp", "new", "cur" }) |sub| try maildir.createDirPath(io, sub);

        const name = try uniqueName(io, allocator);
        errdefer allocator.free(name);
        var tmp_buf: [std.fs.max_name_bytes + 4]u8 = undefined;
        var new_buf: [std.fs.max_name_bytes + 4]u8 = undefined;
        const tmp_path = try std.fmt.bufPrint(&tmp_buf, "tmp/{s}", .{name});
        const new_path = try std.fmt.bufPrint(&new_buf, "new/{s}", .{name});

        const file = try maildir.createFile(io, tmp_path, .{ .exclusive = true });
        errdefer maildir.deleteFile(io, tmp_path) catch {};
        {
            defer file.close(io);
            try file.writeStreamingAll(io, header);
            try file.writeStreamingAll(io, body);
            try file.sync(io);
        }
        try maildir.rename(tmp_path, maildir, new_path, io);
        return name;
    }

    /// Lists INBOX oldest first, moving anything in `new/` to `cur/`.
    pub fn listMailbox(self: Storage, io: Io, allocator: std.mem.Allocator, tenant: []const u8, domain: []const u8, user: []const u8) ![]Message {
        const maildir_path = try self.maildirPath(allocator, tenant, domain, user);
        defer allocator.free(maildir_path);
        var maildir = Io.Dir.cwd().openDir(io, maildir_path, .{}) catch |err| switch (err) {
            error.FileNotFound => return &.{},
            else => return err,
        };
        defer maildir.close(io);
        try claimNew(io, allocator, maildir);

        var cur = maildir.openDir(io, "cur", .{ .iterate = true }) catch |err| switch (err) {
            error.FileNotFound => return &.{},
            else => return err,
        };
        defer cur.close(io);

        var messages = std.ArrayList(Message).empty;
        defer messages.deinit(allocator);
        errdefer for (messages.items) |message| allocator.free(message.path);

        var it = cur.iterate();
        while (try it.next(io)) |entry| {
            if (entry.kind != .file) continue;
            const stat = try cur.statFile(io, entry.name, .{});
            const path = try std.fs.path.join(allocator, &.{ maildir_path, "cur", entry.name });
            errdefer allocator.free(path);
            try messages.append(allocator, .{ .path = path, .size = stat.size, .flags = .fromFileName(entry.name) });
        }
        std.sort.pdq(Message, messages.items, {}, olderFirst);
        return messages.toOwnedSlice(allocator);
    }

    pub fn readMessage(io: Io, allocator: std.mem.Allocator, message: Message) ![]u8 {
        return Io.Dir.cwd().readFileAlloc(io, message.path, allocator, .limited(1024 * 1024));
    }

    /// Renames the message so its file name carries `flags`.
    pub fn setFlags(io: Io, allocator: std.mem.Allocator, message: *Message, flags: MessageFlags) !void {
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

    pub fn merge(self: MessageFlags, other: MessageFlags) MessageFlags {
        return .{
            .seen = self.seen or other.seen,
            .answered = self.answered or other.answered,
            .flagged = self.flagged or other.flagged,
            .deleted = self.deleted or other.deleted,
            .draft = self.draft or other.draft,
        };
    }

    /// IMAP flag list, e.g. `(\Seen \Flagged)`.
    pub fn format(self: MessageFlags, allocator: std.mem.Allocator) ![]u8 {
        var list = std.ArrayList(u8).empty;
        errdefer list.deinit(allocator);
        try list.append(allocator, '(');
        for ([_]struct { bool, []const u8 }{ .{ self.seen, "\\Seen" }, .{ self.answered, "\\Answered" }, .{ self.flagged, "\\Flagged" }, .{ self.deleted, "\\Deleted" }, .{ self.draft, "\\Draft" } }) |flag| {
            if (!flag[0]) continue;
            if (list.items.len > 1) try list.append(allocator, ' ');
            try list.appendSlice(allocator, flag[1]);
        }
        try list.append(allocator, ')');
        return list.toOwnedSlice(allocator);
    }
};

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

fn claimNew(io: Io, allocator: std.mem.Allocator, maildir: Io.Dir) !void {
    var new = maildir.openDir(io, "new", .{ .iterate = true }) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    defer new.close(io);
    try maildir.createDirPath(io, "cur");

    // Collect first: renaming entries out of a directory while iterating it is unspecified.
    var names = std.ArrayList([]u8).empty;
    defer {
        for (names.items) |name| allocator.free(name);
        names.deinit(allocator);
    }
    var it = new.iterate();
    while (try it.next(io)) |entry| {
        if (entry.kind != .file) continue;
        const name = try allocator.dupe(u8, entry.name);
        errdefer allocator.free(name);
        try names.append(allocator, name);
    }

    var from_buf: [std.fs.max_name_bytes + 4]u8 = undefined;
    var to_buf: [std.fs.max_name_bytes + 8]u8 = undefined;
    for (names.items) |name| {
        const from = try std.fmt.bufPrint(&from_buf, "new/{s}", .{name});
        const to = try std.fmt.bufPrint(&to_buf, "cur/{s}:2,", .{name});
        maildir.rename(from, maildir, to, io) catch |err| switch (err) {
            error.FileNotFound => {}, // claimed by a concurrent session
            else => return err,
        };
    }
}

fn baseName(path: []const u8) []const u8 {
    const name = std.fs.path.basename(path);
    return name[0 .. std.mem.indexOf(u8, name, ":2,") orelse name.len];
}

fn olderFirst(_: void, a: Message, b: Message) bool {
    return std.mem.order(u8, baseName(a.path), baseName(b.path)) == .lt;
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

test "listing claims new mail into cur, oldest first" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try testRoot(allocator, &tmp);
    defer allocator.free(root);
    const storage = Storage.init(root);

    for ([_][]const u8{ "one", "two", "three" }) |body| allocator.free(try storage.deliver(io, allocator, "acme", "example.com", "alice", "", body));

    const messages = try storage.listMailbox(io, allocator, "acme", "example.com", "alice");
    defer freeMessages(allocator, messages);
    try std.testing.expectEqual(@as(usize, 3), messages.len);
    for (messages, [_][]const u8{ "one", "two", "three" }) |message, expected| {
        try std.testing.expect(std.mem.indexOf(u8, message.path, "/cur/") != null);
        try std.testing.expect(std.mem.endsWith(u8, message.path, ":2,"));
        const body = try Storage.readMessage(io, allocator, message);
        defer allocator.free(body);
        try std.testing.expectEqualStrings(expected, body);
    }
}

test "flags live in the file name and survive relisting" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try testRoot(allocator, &tmp);
    defer allocator.free(root);
    const storage = Storage.init(root);

    allocator.free(try storage.deliver(io, allocator, "acme", "example.com", "alice", "Subject: x\r\n", "hello"));
    {
        const messages = try storage.listMailbox(io, allocator, "acme", "example.com", "alice");
        defer freeMessages(allocator, messages);
        try Storage.setFlags(io, allocator, &messages[0], .{ .seen = true, .flagged = true, .deleted = true });
        try std.testing.expect(std.mem.endsWith(u8, messages[0].path, ":2,FST"));
    }

    const messages = try storage.listMailbox(io, allocator, "acme", "example.com", "alice");
    defer freeMessages(allocator, messages);
    try std.testing.expectEqual(MessageFlags{ .seen = true, .flagged = true, .deleted = true }, messages[0].flags);

    try Storage.deleteMessage(io, messages[0]);
    const after = try storage.listMailbox(io, allocator, "acme", "example.com", "alice");
    defer freeMessages(allocator, after);
    try std.testing.expectEqual(@as(usize, 0), after.len);
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

    const text = try (MessageFlags{ .seen = true, .flagged = true }).format(std.testing.allocator);
    defer std.testing.allocator.free(text);
    try std.testing.expectEqualStrings("(\\Seen \\Flagged)", text);
}

test "account index path is stable" {
    const allocator = std.testing.allocator;
    const path = try Storage.init("data").accountIndexPath(allocator, "tenant-a", "example.com");
    defer allocator.free(path);
    try std.testing.expectEqualStrings("data/tenants/tenant-a/domains/example.com/accounts.txt", path);
}

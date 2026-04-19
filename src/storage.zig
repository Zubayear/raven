const std = @import("std");
const Io = std.Io;

pub const Storage = struct {
    root_dir: []const u8,
    next_inbound_id: u64 = 0,

    pub fn init(root_dir: []const u8) Storage {
        return .{ .root_dir = root_dir };
    }

    pub fn ensureLayout(self: Storage, io: Io, allocator: std.mem.Allocator) !void {
        try ensurePath(io, self.root_dir);
        try ensureJoined(io, allocator, &.{ self.root_dir, "queue" });
        try ensureJoined(io, allocator, &.{ self.root_dir, "queue", "inbound" });
        try ensureJoined(io, allocator, &.{ self.root_dir, "queue", "outbound" });
        try ensureJoined(io, allocator, &.{ self.root_dir, "tenants" });
    }

    pub fn tenantRoot(self: Storage, allocator: std.mem.Allocator, tenant: []const u8) ![]u8 {
        return std.fs.path.join(allocator, &.{ self.root_dir, "tenants", tenant });
    }

    pub fn mailboxRoot(
        self: Storage,
        allocator: std.mem.Allocator,
        tenant: []const u8,
        domain: []const u8,
        user: []const u8,
    ) ![]u8 {
        return std.fs.path.join(allocator, &.{
            self.root_dir,
            "tenants",
            tenant,
            "domains",
            domain,
            "users",
            user,
            "Maildir",
        });
    }

    pub fn messageStorePath(
        self: Storage,
        allocator: std.mem.Allocator,
        tenant: []const u8,
        domain: []const u8,
        user: []const u8,
        filename: []const u8,
    ) ![]u8 {
        return std.fs.path.join(allocator, &.{
            self.root_dir,
            "tenants",
            tenant,
            "domains",
            domain,
            "users",
            user,
            "Maildir",
            "new",
            filename,
        });
    }

    pub fn mailboxNewDir(
        self: Storage,
        allocator: std.mem.Allocator,
        tenant: []const u8,
        domain: []const u8,
        user: []const u8,
    ) ![]u8 {
        return std.fs.path.join(allocator, &.{
            self.root_dir,
            "tenants",
            tenant,
            "domains",
            domain,
            "users",
            user,
            "Maildir",
            "new",
        });
    }

    pub const MailboxMessage = struct {
        name: []u8,
        path: []u8,
        size: u64,
        sequence: u64,
    };

    pub fn listMailboxMessages(
        self: Storage,
        io: Io,
        allocator: std.mem.Allocator,
        tenant: []const u8,
        domain: []const u8,
        user: []const u8,
    ) ![]MailboxMessage {
        const mailbox_new_dir = try self.mailboxNewDir(allocator, tenant, domain, user);
        defer allocator.free(mailbox_new_dir);

        var dir = Io.Dir.cwd().openDir(io, mailbox_new_dir, .{ .iterate = true }) catch |err| switch (err) {
            error.FileNotFound => return &.{},
            else => return err,
        };
        defer dir.close(io);

        var items = std.ArrayList(MailboxMessage).empty;
        errdefer freeMailboxMessages(allocator, items.items);

        var iter = dir.iterateAssumeFirstIteration();
        while (try iter.next(io)) |entry| {
            if (entry.kind != .file) continue;
            if (!std.mem.endsWith(u8, entry.name, ".eml")) continue;

            const sequence = parseSequence(entry.name) orelse continue;
            const path = try std.fs.path.join(allocator, &.{ mailbox_new_dir, entry.name });
            const stat = try dir.statFile(io, entry.name, .{});

            try items.append(allocator, .{
                .name = try allocator.dupe(u8, entry.name),
                .path = path,
                .size = stat.size,
                .sequence = sequence,
            });
        }

        std.sort.insertion(MailboxMessage, items.items, {}, lessThanMailboxMessage);
        return try items.toOwnedSlice(allocator);
    }

    pub fn readMailboxMessage(
        self: Storage,
        io: Io,
        allocator: std.mem.Allocator,
        tenant: []const u8,
        domain: []const u8,
        user: []const u8,
        name: []const u8,
    ) ![]u8 {
        const path = try std.fs.path.join(allocator, &.{
            self.root_dir,
            "tenants",
            tenant,
            "domains",
            domain,
            "users",
            user,
            "Maildir",
            "new",
            name,
        });
        defer allocator.free(path);

        return Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(1024 * 1024));
    }

    pub fn queueInboundDir(self: Storage, allocator: std.mem.Allocator) ![]u8 {
        return std.fs.path.join(allocator, &.{ self.root_dir, "queue", "inbound" });
    }

    pub fn tenantIndexPath(self: Storage, allocator: std.mem.Allocator) ![]u8 {
        return std.fs.path.join(allocator, &.{ self.root_dir, "tenants", "index.txt" });
    }

    pub fn aliasIndexPath(
        self: Storage,
        allocator: std.mem.Allocator,
        tenant: []const u8,
        domain: []const u8,
    ) ![]u8 {
        return std.fs.path.join(allocator, &.{
            self.root_dir,
            "tenants",
            tenant,
            "domains",
            domain,
            "aliases.txt",
        });
    }

    pub fn writeInboundMessage(
        self: *Storage,
        io: Io,
        allocator: std.mem.Allocator,
        message: []const u8,
    ) ![]u8 {
        const queue_dir = try self.queueInboundDir(allocator);
        defer allocator.free(queue_dir);

        try ensurePath(io, queue_dir);

        const id = self.next_inbound_id;
        self.next_inbound_id += 1;

        var filename_buf: [64]u8 = undefined;
        const filename = try std.fmt.bufPrint(&filename_buf, "{d}.eml", .{id});

        const full_path = try std.fs.path.join(allocator, &.{ queue_dir, filename });
        errdefer allocator.free(full_path);

        var file = try Io.Dir.cwd().createFile(io, full_path, .{
            .exclusive = true,
            .truncate = false,
        });
        defer file.close(io);

        try file.writeStreamingAll(io, message);

        return full_path;
    }

    pub fn deliverMailboxMessage(
        self: *Storage,
        io: Io,
        allocator: std.mem.Allocator,
        tenant: []const u8,
        domain: []const u8,
        user: []const u8,
        message: []const u8,
    ) ![]u8 {
        const mailbox_new_dir = try self.mailboxNewDir(allocator, tenant, domain, user);
        defer allocator.free(mailbox_new_dir);

        try ensurePath(io, mailbox_new_dir);

        const id = self.next_inbound_id;
        self.next_inbound_id += 1;

        var filename_buf: [64]u8 = undefined;
        const filename = try std.fmt.bufPrint(&filename_buf, "{d}.eml", .{id});

        const full_path = try std.fs.path.join(allocator, &.{ mailbox_new_dir, filename });
        errdefer allocator.free(full_path);

        var file = try Io.Dir.cwd().createFile(io, full_path, .{
            .exclusive = true,
            .truncate = false,
        });
        defer file.close(io);

        try file.writeStreamingAll(io, message);
        return full_path;
    }
};

fn parseSequence(name: []const u8) ?u64 {
    if (!std.mem.endsWith(u8, name, ".eml")) return null;
    const stem = name[0 .. name.len - 4];
    return std.fmt.parseInt(u64, stem, 10) catch null;
}

fn lessThanMailboxMessage(_: void, lhs: Storage.MailboxMessage, rhs: Storage.MailboxMessage) bool {
    return lhs.sequence < rhs.sequence;
}

pub fn freeMailboxMessages(allocator: std.mem.Allocator, items: []Storage.MailboxMessage) void {
    for (items) |item| {
        allocator.free(item.name);
        allocator.free(item.path);
    }
    allocator.free(items);
}

fn ensurePath(io: Io, path: []const u8) !void {
    try Io.Dir.cwd().createDirPath(io, path);
}

fn ensureJoined(io: Io, allocator: std.mem.Allocator, parts: []const []const u8) !void {
    const path = try std.fs.path.join(allocator, parts);
    defer allocator.free(path);
    try ensurePath(io, path);
}

test "mailbox paths are stable" {
    const allocator = std.testing.allocator;
    const storage = Storage.init("data");

    const path = try storage.mailboxRoot(allocator, "tenant-a", "example.com", "alice");
    defer allocator.free(path);

    try std.testing.expectEqualStrings(
        "data/tenants/tenant-a/domains/example.com/users/alice/Maildir",
        path,
    );
}

test "mailbox new dir path is stable" {
    const allocator = std.testing.allocator;
    const storage = Storage.init("data");

    const path = try storage.mailboxNewDir(allocator, "tenant-a", "example.com", "alice");
    defer allocator.free(path);

    try std.testing.expectEqualStrings(
        "data/tenants/tenant-a/domains/example.com/users/alice/Maildir/new",
        path,
    );
}

test "mailbox message listing is ordered" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.createDirPath(std.testing.io, "tenants/acme/domains/example.com/users/alice/Maildir/new");
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "tenants/acme/domains/example.com/users/alice/Maildir/new/2.eml", .data = "two" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "tenants/acme/domains/example.com/users/alice/Maildir/new/10.eml", .data = "ten" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "tenants/acme/domains/example.com/users/alice/Maildir/new/1.eml", .data = "one" });

    const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", tmp.sub_path[0..] });
    defer allocator.free(root);

    const storage = Storage.init(root);
    const messages = try storage.listMailboxMessages(std.testing.io, allocator, "acme", "example.com", "alice");
    defer freeMailboxMessages(allocator, messages);

    try std.testing.expectEqual(@as(usize, 3), messages.len);
    try std.testing.expectEqualStrings("1.eml", messages[0].name);
    try std.testing.expectEqualStrings("2.eml", messages[1].name);
    try std.testing.expectEqualStrings("10.eml", messages[2].name);
}

test "mailbox message read returns content" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.createDirPath(std.testing.io, "tenants/acme/domains/example.com/users/alice/Maildir/new");
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "tenants/acme/domains/example.com/users/alice/Maildir/new/1.eml", .data = "hello" });

    const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", tmp.sub_path[0..] });
    defer allocator.free(root);

    const storage = Storage.init(root);
    const data = try storage.readMailboxMessage(std.testing.io, allocator, "acme", "example.com", "alice", "1.eml");
    defer allocator.free(data);

    try std.testing.expectEqualStrings("hello", data);
}

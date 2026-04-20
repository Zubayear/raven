const std = @import("std");
const Io = std.Io;

const Storage = @import("storage.zig").Storage;

pub const AccountStore = struct {
    entries: []Entry = &.{},

    pub const Entry = struct {
        user: []u8,
        password_hash: []u8,
    };

    pub fn load(allocator: std.mem.Allocator, io: Io, storage: Storage, tenant: []const u8, domain: []const u8) !AccountStore {
        const path = try storage.accountIndexPath(allocator, tenant, domain);
        defer allocator.free(path);

        const raw = storageReadAccounts(io, allocator, path) catch |err| switch (err) {
            error.FileNotFound => return .{},
            else => return err,
        };
        defer allocator.free(raw);

        return try parse(allocator, raw);
    }

    pub fn deinit(self: *AccountStore, allocator: std.mem.Allocator) void {
        if (self.entries.len > 0) freeEntries(allocator, self.entries);
        self.* = .{};
    }

    pub fn verify(self: *const AccountStore, user: []const u8, password: []const u8) bool {
        const entry = self.find(user) orelse return false;
        var hash_buf: [64]u8 = undefined;
        const computed = passwordHashHex(password, &hash_buf);
        return std.ascii.eqlIgnoreCase(entry.password_hash, computed);
    }

    fn find(self: *const AccountStore, user: []const u8) ?Entry {
        for (self.entries) |entry| {
            if (std.mem.eql(u8, entry.user, user)) return entry;
        }
        return null;
    }
};

fn storageReadAccounts(io: Io, allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    return Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(32 * 1024));
}

fn parse(allocator: std.mem.Allocator, raw: []const u8) !AccountStore {
    var entries = std.ArrayList(AccountStore.Entry).empty;
    errdefer freeEntries(allocator, entries.items);

    var lines = std.mem.tokenizeScalar(u8, raw, '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (trimmed.len == 0 or trimmed[0] == '#') continue;

        var tokens = std.mem.tokenizeAny(u8, trimmed, " \t=");
        const user = tokens.next() orelse return error.InvalidAccountIndex;
        const password_hash = tokens.next() orelse return error.InvalidAccountIndex;
        if (password_hash.len != 64) return error.InvalidAccountIndex;

        try entries.append(allocator, .{
            .user = try allocator.dupe(u8, user),
            .password_hash = try allocator.dupe(u8, password_hash),
        });
    }

    return .{ .entries = try entries.toOwnedSlice(allocator) };
}

pub fn parseForTest(allocator: std.mem.Allocator, raw: []const u8) !AccountStore {
    return parse(allocator, raw);
}

pub fn passwordHashHex(password: []const u8, out_buf: *[64]u8) []const u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(password, &digest, .{});
    const encoded = std.fmt.bytesToHex(digest, .lower);
    out_buf.* = encoded;
    return out_buf[0..];
}

fn freeEntries(allocator: std.mem.Allocator, entries: []AccountStore.Entry) void {
    for (entries) |entry| {
        allocator.free(entry.user);
        allocator.free(entry.password_hash);
    }
    allocator.free(entries);
}

test "account store parses entries" {
    const allocator = std.testing.allocator;
    var hash_buf: [64]u8 = undefined;
    const hash = passwordHashHex("secret", &hash_buf);
    const raw = try std.fmt.allocPrint(allocator, "alice {s}\n# comment\nbob {s}\n", .{ hash, hash });
    defer allocator.free(raw);

    var store = try parse(allocator, raw);
    defer store.deinit(allocator);

    try std.testing.expectEqualStrings("alice", store.entries[0].user);
    try std.testing.expectEqualStrings(hash, store.entries[0].password_hash);
    try std.testing.expectEqualStrings("bob", store.entries[1].user);
}

test "account store verifies password" {
    const allocator = std.testing.allocator;
    var hash_buf: [64]u8 = undefined;
    const hash = passwordHashHex("secret", &hash_buf);
    const raw = try std.fmt.allocPrint(allocator, "alice {s}\n", .{hash});
    defer allocator.free(raw);

    var store = try parse(allocator, raw);
    defer store.deinit(allocator);

    try std.testing.expect(store.verify("alice", "secret"));
    try std.testing.expect(!store.verify("alice", "wrong"));
    try std.testing.expect(!store.verify("bob", "secret"));
}

test "account store loads from filesystem" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var hash_buf: [64]u8 = undefined;
    const hash = passwordHashHex("secret", &hash_buf);
    const accounts = try std.fmt.allocPrint(allocator, "alice {s}\n", .{hash});
    defer allocator.free(accounts);

    try tmp.dir.createDirPath(std.testing.io, "tenants/acme/domains/example.com");
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "tenants/acme/domains/example.com/accounts.txt",
        .data = accounts,
    });

    const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", tmp.sub_path[0..] });
    defer allocator.free(root);

    var store = try AccountStore.load(allocator, std.testing.io, Storage.init(root), "acme", "example.com");
    defer store.deinit(allocator);

    try std.testing.expect(store.verify("alice", "secret"));
}

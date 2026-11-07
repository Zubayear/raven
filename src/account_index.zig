const std = @import("std");
const Io = std.Io;

const Storage = @import("storage.zig").Storage;
const TenantCatalog = @import("tenant_index.zig").TenantCatalog;
const address = @import("address.zig");

/// A mailbox owner. All names come from the index files, never from client
/// input, so they are safe to use in paths.
pub const Identity = struct {
    tenant: []u8,
    domain: []u8,
    user: []u8,

    pub fn init(allocator: std.mem.Allocator, tenant: []const u8, domain: []const u8, user: []const u8) !Identity {
        const owned_tenant = try allocator.dupe(u8, tenant);
        errdefer allocator.free(owned_tenant);
        const owned_domain = try allocator.dupe(u8, domain);
        errdefer allocator.free(owned_domain);
        return .{ .tenant = owned_tenant, .domain = owned_domain, .user = try allocator.dupe(u8, user) };
    }

    pub fn deinit(self: Identity, allocator: std.mem.Allocator) void {
        allocator.free(self.tenant);
        allocator.free(self.domain);
        allocator.free(self.user);
    }
};

/// Checks `login` (`user@domain`) and `password` against the domain's
/// accounts. Every failure is `error.AuthFailed`, so callers can't leak why.
pub fn authenticate(allocator: std.mem.Allocator, io: Io, storage: Storage, catalog: *const TenantCatalog, login: []const u8, password: []const u8) !Identity {
    const addr = address.parse(login) catch return error.AuthFailed;
    const hosted = catalog.find(addr.domain) orelse return error.AuthFailed;
    var accounts = try AccountStore.load(allocator, io, storage, hosted.tenant, hosted.domain);
    defer accounts.deinit(allocator);
    const account = accounts.find(addr.user) orelse return error.AuthFailed;
    if (!account.verify(password)) return error.AuthFailed;
    return Identity.init(allocator, hosted.tenant, hosted.domain, account.user);
}

pub const AccountStore = struct {
    entries: []Entry = &.{},

    pub const Entry = struct {
        user: []u8,
        password_hash: []u8,

        pub fn verify(self: Entry, password: []const u8) bool {
            var hash_buf: [64]u8 = undefined;
            return std.ascii.eqlIgnoreCase(self.password_hash, passwordHashHex(password, &hash_buf));
        }
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
        return entry.verify(password);
    }

    /// Local parts are matched case-insensitively.
    pub fn find(self: *const AccountStore, user: []const u8) ?Entry {
        for (self.entries) |entry| {
            if (std.ascii.eqlIgnoreCase(entry.user, user)) return entry;
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

test "authenticate checks domain, user and password" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var hash_buf: [64]u8 = undefined;
    const accounts = try std.fmt.allocPrint(allocator, "alice {s}\n", .{passwordHashHex("secret", &hash_buf)});
    defer allocator.free(accounts);
    try tmp.dir.createDirPath(std.testing.io, "tenants/acme/domains/example.com");
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "tenants/acme/domains/example.com/accounts.txt", .data = accounts });
    const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", tmp.sub_path[0..] });
    defer allocator.free(root);

    var catalog = try @import("tenant_index.zig").parseForTest(allocator, "tenant acme example.com\n");
    defer catalog.deinit(allocator);
    const storage = Storage.init(root);

    const identity = try authenticate(allocator, std.testing.io, storage, &catalog, "Alice@EXAMPLE.com", "secret");
    defer identity.deinit(allocator);
    try std.testing.expectEqualStrings("acme", identity.tenant);
    try std.testing.expectEqualStrings("example.com", identity.domain);
    try std.testing.expectEqualStrings("alice", identity.user);

    for ([_][2][]const u8{
        .{ "alice@example.com", "wrong" },
        .{ "bob@example.com", "secret" },
        .{ "alice@other.com", "secret" },
        .{ "../alice@example.com", "secret" },
    }) |attempt| {
        try std.testing.expectError(error.AuthFailed, authenticate(allocator, std.testing.io, storage, &catalog, attempt[0], attempt[1]));
    }
}

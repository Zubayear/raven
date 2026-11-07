//! `accounts.txt`: one account per line, `<user> <argon2id PHC string>`.
//! Create lines with `raven passwd`.
const std = @import("std");
const Io = std.Io;
const argon2 = std.crypto.pwhash.argon2;

const Storage = @import("storage.zig").Storage;
const TenantCatalog = @import("tenant_index.zig").TenantCatalog;
const address = @import("address.zig");
const AliasTable = @import("alias_index.zig").AliasTable;

/// OWASP's recommendation for argon2id (19 MiB, 2 passes). Each login holds
/// that much memory while it verifies.
const hash_params = argon2.Params.owasp_2id;

/// Verified when the user does not exist, so a failed login takes as long
/// either way and response times don't reveal which accounts exist.
const dummy_hash = "$argon2id$v=19$m=19456,t=2,p=1$cmF2ZW5kdW1teXNhbHQ$Hh8Xnzvbbj6HTZ8nHArp0n2LBnz5/YF6jXTkpdyXl2U";

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
    const account = accounts.find(addr.user) orelse {
        _ = verifyPassword(allocator, io, dummy_hash, password);
        return error.AuthFailed;
    };
    if (!verifyPassword(allocator, io, account.password_hash, password)) return error.AuthFailed;
    return Identity.init(allocator, hosted.tenant, hosted.domain, account.user);
}

/// RFC 4616 PLAIN: base64("authzid\0authcid\0password").
pub fn authenticatePlain(allocator: std.mem.Allocator, io: Io, storage: Storage, catalog: *const TenantCatalog, encoded: []const u8) !Identity {
    const decoded = try decodeBase64Payload(allocator, std.mem.trim(u8, encoded, " \t"));
    defer allocator.free(decoded);

    var fields = std.mem.splitScalar(u8, decoded, 0);
    const authzid = fields.next() orelse return error.AuthFailed;
    const login = fields.next() orelse return error.AuthFailed;
    const password = fields.next() orelse return error.AuthFailed;
    if (fields.next() != null or password.len == 0) return error.AuthFailed;
    // Acting as another user is not supported.
    if (authzid.len != 0 and !std.ascii.eqlIgnoreCase(authzid, login)) return error.AuthFailed;

    return authenticate(allocator, io, storage, catalog, login, password);
}

fn decodeBase64Payload(allocator: std.mem.Allocator, encoded: []const u8) ![]u8 {
    const clean = std.mem.trim(u8, encoded, " \t");
    const codecs = [_]std.base64.Codecs{ std.base64.standard, std.base64.standard_no_pad };

    for (codecs) |codec| {
        const decoder = &codec.Decoder;
        const size = decoder.calcSizeForSlice(clean) catch continue;
        const buf = try allocator.alloc(u8, size);
        decoder.decode(buf, clean) catch {
            allocator.free(buf);
            continue;
        };
        return buf;
    }
    return error.AuthFailed;
}

/// Maps a recipient address to a local mailbox: the domain must be hosted
/// and the user an account, directly or through an alias. `+tag` is ignored.
pub fn resolveMailbox(allocator: std.mem.Allocator, io: Io, storage: Storage, catalog: *const TenantCatalog, addr: address.Address) !Identity {
    const hosted = catalog.find(addr.domain) orelse return error.NotHosted;

    var aliases = try AliasTable.load(allocator, io, storage, hosted.tenant, hosted.domain);
    defer aliases.deinit(allocator);
    var accounts = try AccountStore.load(allocator, io, storage, hosted.tenant, hosted.domain);
    defer accounts.deinit(allocator);

    const account = accounts.find(aliases.find(addr.user) orelse addr.user) orelse return error.UnknownUser;
    return Identity.init(allocator, hosted.tenant, hosted.domain, account.user);
}

/// Returns an argon2id PHC string for `password`; the caller owns it.
pub fn hashPassword(allocator: std.mem.Allocator, io: Io, password: []const u8) ![]u8 {
    var buf: [128]u8 = undefined;
    return allocator.dupe(u8, try argon2.strHash(password, .{ .allocator = allocator, .params = hash_params }, &buf, io));
}

fn verifyPassword(allocator: std.mem.Allocator, io: Io, phc: []const u8, password: []const u8) bool {
    argon2.strVerify(phc, password, .{ .allocator = allocator }, io) catch return false;
    return true;
}

pub const AccountStore = struct {
    entries: []Entry = &.{},

    pub const Entry = struct {
        user: []u8,
        password_hash: []u8,
    };

    pub fn load(allocator: std.mem.Allocator, io: Io, storage: Storage, tenant: []const u8, domain: []const u8) !AccountStore {
        const path = try storage.accountIndexPath(allocator, tenant, domain);
        defer allocator.free(path);

        const raw = Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(256 * 1024)) catch |err| switch (err) {
            error.FileNotFound => return .{},
            else => return err,
        };
        defer allocator.free(raw);
        return parse(allocator, raw);
    }

    pub fn deinit(self: *AccountStore, allocator: std.mem.Allocator) void {
        freeEntries(allocator, self.entries);
        self.* = .{};
    }

    /// Local parts are matched case-insensitively.
    pub fn find(self: *const AccountStore, user: []const u8) ?Entry {
        for (self.entries) |entry| {
            if (std.ascii.eqlIgnoreCase(entry.user, user)) return entry;
        }
        return null;
    }
};

fn parse(allocator: std.mem.Allocator, raw: []const u8) !AccountStore {
    var entries = std.ArrayList(AccountStore.Entry).empty;
    errdefer {
        for (entries.items) |entry| freeEntry(allocator, entry);
        entries.deinit(allocator);
    }

    var lines = std.mem.tokenizeScalar(u8, raw, '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (trimmed.len == 0 or trimmed[0] == '#') continue;

        var tokens = std.mem.tokenizeAny(u8, trimmed, " \t");
        const user = tokens.next() orelse return error.InvalidAccountIndex;
        const password_hash = tokens.next() orelse return error.InvalidAccountIndex;
        // Only argon2id; the old unsalted SHA-256 hex hashes are refused.
        if (tokens.next() != null or !std.mem.startsWith(u8, password_hash, "$argon2id$")) return error.InvalidAccountIndex;

        const owned_user = try allocator.dupe(u8, user);
        errdefer allocator.free(owned_user);
        const owned_hash = try allocator.dupe(u8, password_hash);
        errdefer allocator.free(owned_hash);
        try entries.append(allocator, .{ .user = owned_user, .password_hash = owned_hash });
    }
    return .{ .entries = try entries.toOwnedSlice(allocator) };
}

fn freeEntries(allocator: std.mem.Allocator, entries: []AccountStore.Entry) void {
    if (entries.len == 0) return;
    for (entries) |entry| freeEntry(allocator, entry);
    allocator.free(entries);
}

fn freeEntry(allocator: std.mem.Allocator, entry: AccountStore.Entry) void {
    allocator.free(entry.user);
    allocator.free(entry.password_hash);
}

/// A cheap (but real) argon2id hash for tests; production uses `hashPassword`.
pub fn hashForTest(allocator: std.mem.Allocator, password: []const u8) ![]u8 {
    var buf: [128]u8 = undefined;
    return allocator.dupe(u8, try argon2.strHash(password, .{ .allocator = allocator, .params = .{ .t = 1, .m = 8, .p = 1 } }, &buf, std.testing.io));
}

/// Writes `accounts.txt` for tenant acme / example.com under `dir`.
pub fn writeTestAccounts(allocator: std.mem.Allocator, dir: Io.Dir, users: []const []const u8, password: []const u8) !void {
    const hash = try hashForTest(allocator, password);
    defer allocator.free(hash);
    var text: Io.Writer.Allocating = .init(allocator);
    defer text.deinit();
    for (users) |user| try text.writer.print("{s} {s}\n", .{ user, hash });
    try dir.createDirPath(std.testing.io, "tenants/acme/domains/example.com");
    try dir.writeFile(std.testing.io, .{ .sub_path = "tenants/acme/domains/example.com/accounts.txt", .data = text.written() });
}

test "hashPassword produces argon2id that verifies" {
    const allocator = std.testing.allocator;
    const hash = try hashPassword(allocator, std.testing.io, "correct horse");
    defer allocator.free(hash);
    try std.testing.expect(std.mem.startsWith(u8, hash, "$argon2id$v=19$m=19456,t=2,p=1$"));
    try std.testing.expect(verifyPassword(allocator, std.testing.io, hash, "correct horse"));
    try std.testing.expect(!verifyPassword(allocator, std.testing.io, hash, "wrong horse"));
}

test "dummy hash runs a full verification" {
    // A parse error would make unknown users fail faster than known ones.
    try std.testing.expectError(error.PasswordVerificationFailed, argon2.strVerify(dummy_hash, "anything", .{ .allocator = std.testing.allocator }, std.testing.io));
}

test "account store parses entries and refuses legacy hashes" {
    const allocator = std.testing.allocator;
    var store = try parse(allocator, "# comment\nalice $argon2id$v=19$m=8,t=1,p=1$c2FsdHNhbHQ$aGFzaA\nBob $argon2id$x\n");
    defer store.deinit(allocator);
    try std.testing.expectEqualStrings("alice", store.entries[0].user);
    try std.testing.expectEqualStrings("Bob", store.find("bob").?.user);
    try std.testing.expect(store.find("carol") == null);

    try std.testing.expectError(error.InvalidAccountIndex, parse(allocator, "alice 2bb80d537b1da3e38bd30361aa855686bde0eacd7162fef6a25fe97bf527a25b\n"));
    try std.testing.expectError(error.InvalidAccountIndex, parse(allocator, "alice\n"));
    try std.testing.expectError(error.InvalidAccountIndex, parse(allocator, "alice $argon2id$a extra\n"));
}

test "authenticate checks domain, user and password" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try writeTestAccounts(allocator, tmp.dir, &.{"alice"}, "secret");
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

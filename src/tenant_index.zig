//! `tenants/index.txt`: which tenant hosts which domains, one line per
//! tenant: `tenant <name> <domain>...`. Each domain belongs to one tenant.
const std = @import("std");
const Io = std.Io;

const Storage = @import("storage.zig").Storage;
const address = @import("address.zig");

pub const TenantCatalog = struct {
    entries: []Entry = &.{},

    pub const Entry = struct {
        tenant: []u8,
        /// Lowercase.
        domains: [][]u8,
    };

    /// A hosted domain, with names taken from the index (safe for paths).
    pub const Hosted = struct {
        tenant: []const u8,
        domain: []const u8,
    };

    pub fn load(allocator: std.mem.Allocator, io: Io, storage: Storage) !TenantCatalog {
        const path = try storage.tenantIndexPath(allocator);
        defer allocator.free(path);

        const raw = Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(64 * 1024)) catch |err| switch (err) {
            error.FileNotFound => return .{},
            else => return err,
        };
        defer allocator.free(raw);

        return try parse(allocator, raw);
    }

    pub fn deinit(self: *TenantCatalog, allocator: std.mem.Allocator) void {
        freeEntries(allocator, self.entries);
        self.* = .{};
    }

    /// Finds the tenant hosting `domain` (case-insensitive).
    pub fn find(self: *const TenantCatalog, domain: []const u8) ?Hosted {
        for (self.entries) |entry| {
            for (entry.domains) |hosted| {
                if (std.ascii.eqlIgnoreCase(hosted, domain)) return .{ .tenant = entry.tenant, .domain = hosted };
            }
        }
        return null;
    }
};

fn parse(allocator: std.mem.Allocator, raw: []const u8) !TenantCatalog {
    var catalog = TenantCatalog{};
    var entries = std.ArrayList(TenantCatalog.Entry).empty;
    errdefer {
        for (entries.items) |entry| freeEntry(allocator, entry);
        entries.deinit(allocator);
    }

    var lines = std.mem.tokenizeScalar(u8, raw, '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (trimmed.len == 0 or trimmed[0] == '#') continue;

        var tokens = std.mem.tokenizeAny(u8, trimmed, " \t=");
        const keyword = tokens.next() orelse continue;
        if (!std.ascii.eqlIgnoreCase(keyword, "tenant")) return error.InvalidTenantIndex;

        // Tenant names and domains become directory names.
        const tenant_name = tokens.next() orelse return error.InvalidTenantIndex;
        if (!address.isLocalPart(tenant_name)) return error.InvalidTenantIndex;

        var domains = std.ArrayList([]u8).empty;
        errdefer {
            for (domains.items) |domain| allocator.free(domain);
            domains.deinit(allocator);
        }
        while (tokens.next()) |domain| {
            if (!address.isDomain(domain)) return error.InvalidTenantIndex;
            catalog.entries = entries.items;
            if (catalog.find(domain) != null or containsIgnoreCase(domains.items, domain)) return error.DuplicateDomain;
            const lower = try std.ascii.allocLowerString(allocator, domain);
            errdefer allocator.free(lower);
            try domains.append(allocator, lower);
        }
        if (domains.items.len == 0) return error.InvalidTenantIndex;

        const tenant = try allocator.dupe(u8, tenant_name);
        errdefer allocator.free(tenant);
        const owned_domains = try domains.toOwnedSlice(allocator);
        errdefer {
            for (owned_domains) |domain| allocator.free(domain);
            allocator.free(owned_domains);
        }
        try entries.append(allocator, .{ .tenant = tenant, .domains = owned_domains });
    }

    return .{ .entries = try entries.toOwnedSlice(allocator) };
}

pub fn parseForTest(allocator: std.mem.Allocator, raw: []const u8) !TenantCatalog {
    return parse(allocator, raw);
}

fn containsIgnoreCase(items: []const []const u8, needle: []const u8) bool {
    for (items) |item| {
        if (std.ascii.eqlIgnoreCase(item, needle)) return true;
    }
    return false;
}

fn freeEntries(allocator: std.mem.Allocator, entries: []TenantCatalog.Entry) void {
    if (entries.len == 0) return;
    for (entries) |entry| freeEntry(allocator, entry);
    allocator.free(entries);
}

fn freeEntry(allocator: std.mem.Allocator, entry: TenantCatalog.Entry) void {
    allocator.free(entry.tenant);
    for (entry.domains) |domain| allocator.free(domain);
    allocator.free(entry.domains);
}

test "tenant catalog finds domains case-insensitively" {
    const allocator = std.testing.allocator;
    var catalog = try parse(allocator,
        \\# comment
        \\tenant acme Example.com mail.example.com
        \\tenant beta beta.com
    );
    defer catalog.deinit(allocator);

    const hosted = catalog.find("EXAMPLE.COM").?;
    try std.testing.expectEqualStrings("acme", hosted.tenant);
    try std.testing.expectEqualStrings("example.com", hosted.domain);
    try std.testing.expectEqualStrings("acme", catalog.find("mail.example.com").?.tenant);
    try std.testing.expectEqualStrings("beta", catalog.find("beta.com").?.tenant);
    try std.testing.expect(catalog.find("fallback.com") == null);
}

test "a domain belongs to exactly one tenant" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.DuplicateDomain, parse(allocator, "tenant acme example.com\ntenant beta EXAMPLE.com\n"));
    try std.testing.expectError(error.DuplicateDomain, parse(allocator, "tenant acme example.com example.com\n"));
}

test "tenant catalog loads from filesystem" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.createDirPath(std.testing.io, "tenants");
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "tenants/index.txt", .data = "tenant acme example.com\n" });

    const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", tmp.sub_path[0..] });
    defer allocator.free(root);

    var catalog = try TenantCatalog.load(allocator, std.testing.io, Storage.init(root));
    defer catalog.deinit(allocator);
    try std.testing.expectEqualStrings("acme", catalog.find("example.com").?.tenant);
}

test "tenant catalog rejects unsafe names" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.InvalidTenantIndex, parse(allocator, "tenant ../escape example.com\n"));
    try std.testing.expectError(error.InvalidTenantIndex, parse(allocator, "tenant acme ../../tmp\n"));
}

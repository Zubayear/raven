const std = @import("std");
const Io = std.Io;

const Storage = @import("storage.zig").Storage;

pub const TenantCatalog = struct {
    entries: []Entry = &.{},

    pub const Entry = struct {
        tenant: []u8,
        domains: [][]u8,
    };

    pub fn load(allocator: std.mem.Allocator, io: Io, storage: Storage) !TenantCatalog {
        const path = try storage.tenantIndexPath(allocator);
        defer allocator.free(path);

        const raw = storageReadIndex(io, allocator, path) catch |err| switch (err) {
            error.FileNotFound => return .{},
            else => return err,
        };
        defer allocator.free(raw);

        return try parse(allocator, raw);
    }

    pub fn deinit(self: *TenantCatalog, allocator: std.mem.Allocator) void {
        if (self.entries.len > 0) freeEntries(allocator, self.entries);
        self.* = .{};
    }

    pub fn resolveTenant(self: *const TenantCatalog, tenant_hint: ?[]const u8, domain: []const u8) ![]const u8 {
        if (tenant_hint) |hint| {
            if (self.findByTenant(hint)) |entry| {
                if (entry.hasDomain(domain)) return entry.tenant;
                return error.DomainNotHosted;
            }
            return error.UnknownTenant;
        }

        if (self.findByDomain(domain)) |entry| {
            return entry.tenant;
        }

        return domain;
    }

    fn findByDomain(self: *const TenantCatalog, domain: []const u8) ?EntryView {
        for (self.entries) |entry| {
            if ((EntryView{ .tenant = entry.tenant, .domains = entry.domains }).hasDomain(domain)) {
                return .{ .tenant = entry.tenant, .domains = entry.domains };
            }
        }
        return null;
    }

    fn findByTenant(self: *const TenantCatalog, tenant: []const u8) ?EntryView {
        for (self.entries) |entry| {
            if (std.mem.eql(u8, entry.tenant, tenant)) {
                return .{ .tenant = entry.tenant, .domains = entry.domains };
            }
        }
        return null;
    }
};

const EntryView = struct {
    tenant: []const u8,
    domains: [][]u8,

    fn hasDomain(self: EntryView, domain: []const u8) bool {
        for (self.domains) |item| {
            if (std.mem.eql(u8, item, domain)) return true;
        }
        return false;
    }
};

fn storageReadIndex(io: Io, allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    return Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(64 * 1024));
}

fn parse(allocator: std.mem.Allocator, raw: []const u8) !TenantCatalog {
    var entries = std.ArrayList(TenantCatalog.Entry).empty;
    errdefer freeEntries(allocator, entries.items);

    var lines = std.mem.tokenizeScalar(u8, raw, '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (trimmed.len == 0 or trimmed[0] == '#') continue;

        var tokens = std.mem.tokenizeAny(u8, trimmed, " \t=");
        const keyword = tokens.next() orelse continue;
        if (!std.ascii.eqlIgnoreCase(keyword, "tenant")) return error.InvalidTenantIndex;

        const tenant_name = tokens.next() orelse return error.InvalidTenantIndex;
        var domains = std.ArrayList([]u8).empty;
        errdefer domains.deinit(allocator);

        while (tokens.next()) |domain| {
            try domains.append(allocator, try allocator.dupe(u8, domain));
        }

        if (domains.items.len == 0) return error.InvalidTenantIndex;

        try entries.append(allocator, .{
            .tenant = try allocator.dupe(u8, tenant_name),
            .domains = try domains.toOwnedSlice(allocator),
        });
    }

    return .{ .entries = try entries.toOwnedSlice(allocator) };
}

pub fn parseForTest(allocator: std.mem.Allocator, raw: []const u8) !TenantCatalog {
    return parse(allocator, raw);
}

fn freeEntries(allocator: std.mem.Allocator, entries: []TenantCatalog.Entry) void {
    if (entries.len == 0) return;

    for (entries) |entry| {
        allocator.free(entry.tenant);
        for (entry.domains) |domain| allocator.free(domain);
        allocator.free(entry.domains);
    }
    allocator.free(entries);
}

test "tenant catalog parses index" {
    const allocator = std.testing.allocator;
    const raw =
        \\# comment
        \\tenant acme example.com mail.example.com
        \\tenant beta beta.com
    ;

    var catalog = try parse(allocator, raw);
    defer catalog.deinit(allocator);

    try std.testing.expectEqualStrings("acme", catalog.entries[0].tenant);
    try std.testing.expectEqualStrings("example.com", catalog.entries[0].domains[0]);
    try std.testing.expectEqualStrings("beta", catalog.entries[1].tenant);
}

test "tenant catalog resolves by domain and hint" {
    const allocator = std.testing.allocator;
    const raw =
        \\tenant acme example.com
        \\tenant beta beta.com
    ;

    var catalog = try parse(allocator, raw);
    defer catalog.deinit(allocator);

    try std.testing.expectEqualStrings("acme", try catalog.resolveTenant(null, "example.com"));
    try std.testing.expectEqualStrings("beta", try catalog.resolveTenant("beta", "beta.com"));
    try std.testing.expectEqualStrings("fallback.com", try catalog.resolveTenant(null, "fallback.com"));
    try std.testing.expectError(error.DomainNotHosted, catalog.resolveTenant("beta", "example.com"));
    try std.testing.expectError(error.UnknownTenant, catalog.resolveTenant("missing", "example.com"));
}

test "tenant catalog loads from filesystem" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.createDirPath(std.testing.io, "tenants");
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "tenants/index.txt",
        .data =
            \\tenant acme example.com
            \\tenant beta beta.com
        ,
    });

    const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", tmp.sub_path[0..] });
    defer allocator.free(root);

    var catalog = try TenantCatalog.load(allocator, std.testing.io, Storage.init(root));
    defer catalog.deinit(allocator);

    try std.testing.expectEqualStrings("acme", try catalog.resolveTenant(null, "example.com"));
    try std.testing.expectEqualStrings("beta", try catalog.resolveTenant(null, "beta.com"));
}

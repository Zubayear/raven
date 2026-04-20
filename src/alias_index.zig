const std = @import("std");
const Io = std.Io;

const Storage = @import("storage.zig").Storage;

pub const AliasTable = struct {
    entries: []Entry = &.{},

    pub const Entry = struct {
        alias: []u8,
        target: []u8,
    };

    pub fn load(allocator: std.mem.Allocator, io: Io, storage: Storage, tenant: []const u8, domain: []const u8) !AliasTable {
        const path = try storage.aliasIndexPath(allocator, tenant, domain);
        defer allocator.free(path);

        const raw = storageReadAlias(io, allocator, path) catch |err| switch (err) {
            error.FileNotFound => return .{},
            else => return err,
        };
        defer allocator.free(raw);

        return try parse(allocator, raw);
    }

    pub fn deinit(self: *AliasTable, allocator: std.mem.Allocator) void {
        if (self.entries.len > 0) freeEntries(allocator, self.entries);
        self.* = .{};
    }

    pub fn resolve(self: *const AliasTable, local_part: []const u8) []const u8 {
        for (self.entries) |entry| {
            if (std.mem.eql(u8, entry.alias, local_part)) return entry.target;
        }
        return local_part;
    }
};

fn storageReadAlias(io: Io, allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    return Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(32 * 1024));
}

fn parse(allocator: std.mem.Allocator, raw: []const u8) !AliasTable {
    var entries = std.ArrayList(AliasTable.Entry).empty;
    errdefer freeEntries(allocator, entries.items);

    var lines = std.mem.tokenizeScalar(u8, raw, '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (trimmed.len == 0 or trimmed[0] == '#') continue;

        var tokens = std.mem.tokenizeAny(u8, trimmed, " \t=");
        const alias = tokens.next() orelse return error.InvalidAliasIndex;
        const target = tokens.next() orelse return error.InvalidAliasIndex;

        try entries.append(allocator, .{
            .alias = try allocator.dupe(u8, alias),
            .target = try allocator.dupe(u8, target),
        });
    }

    return .{ .entries = try entries.toOwnedSlice(allocator) };
}

pub fn parseForTest(allocator: std.mem.Allocator, raw: []const u8) !AliasTable {
    return parse(allocator, raw);
}

fn freeEntries(allocator: std.mem.Allocator, entries: []AliasTable.Entry) void {
    if (entries.len == 0) return;

    for (entries) |entry| {
        allocator.free(entry.alias);
        allocator.free(entry.target);
    }

    allocator.free(entries);
}

test "alias table parses entries" {
    const allocator = std.testing.allocator;
    const raw =
        \\# comment
        \\sales team-sales
        \\support helpdesk
    ;

    var table = try parse(allocator, raw);
    defer table.deinit(allocator);

    try std.testing.expectEqualStrings("sales", table.entries[0].alias);
    try std.testing.expectEqualStrings("team-sales", table.entries[0].target);
    try std.testing.expectEqualStrings("support", table.entries[1].alias);
}

test "alias table resolves or falls back" {
    const allocator = std.testing.allocator;
    const raw =
        \\sales team-sales
        \\support helpdesk
    ;

    var table = try parse(allocator, raw);
    defer table.deinit(allocator);

    try std.testing.expectEqualStrings("team-sales", table.resolve("sales"));
    try std.testing.expectEqualStrings("alice", table.resolve("alice"));
}

test "alias table loads from filesystem" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.createDirPath(std.testing.io, "tenants/acme/domains/example.com");
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "tenants/acme/domains/example.com/aliases.txt",
        .data =
            \\sales team-sales
            \\support helpdesk
        ,
    });

    const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", tmp.sub_path[0..] });
    defer allocator.free(root);

    var table = try AliasTable.load(allocator, std.testing.io, Storage.init(root), "acme", "example.com");
    defer table.deinit(allocator);

    try std.testing.expectEqualStrings("team-sales", table.resolve("sales"));
}

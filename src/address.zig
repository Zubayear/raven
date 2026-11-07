//! Mail address parsing. Local parts and domains end up as filesystem path
//! components, so they are checked against a strict allow-list here, once,
//! before anything else sees them.
const std = @import("std");

pub const Address = struct {
    /// Local part before the last `+`.
    user: []const u8,
    /// Text after the last `+`, if any.
    tag: ?[]const u8,
    domain: []const u8,
};

/// Parses `user[+tag]@domain`, optionally wrapped in `<...>` and followed by
/// ESMTP parameters (`<a@b> SIZE=10`).
pub fn parse(raw: []const u8) error{InvalidAddress}!Address {
    const addr = extract(raw);
    const at = std.mem.lastIndexOfScalar(u8, addr, '@') orelse return error.InvalidAddress;
    const local = addr[0..at];
    const domain = addr[at + 1 ..];
    if (!isLocalPart(local) or !isDomain(domain)) return error.InvalidAddress;

    if (std.mem.lastIndexOfScalar(u8, local, '+')) |plus| {
        if (plus > 0 and plus + 1 < local.len) {
            return .{ .user = local[0..plus], .tag = local[plus + 1 ..], .domain = domain };
        }
    }
    return .{ .user = local, .tag = null, .domain = domain };
}

fn extract(raw: []const u8) []const u8 {
    const trimmed = std.mem.trim(u8, raw, " \t");
    const open = std.mem.indexOfScalar(u8, trimmed, '<') orelse return trimmed;
    const close = std.mem.indexOfScalarPos(u8, trimmed, open, '>') orelse return trimmed;
    return trimmed[open + 1 .. close];
}

/// RFC 5321 dot-atom, minus `/` (atext allows it, but it is a path separator).
/// Also used for tenant names, which become directory names too.
pub fn isLocalPart(s: []const u8) bool {
    if (s.len == 0 or s.len > 64) return false;
    if (s[0] == '.' or s[s.len - 1] == '.' or std.mem.indexOf(u8, s, "..") != null) return false;
    for (s) |ch| {
        if (!std.ascii.isAlphanumeric(ch) and std.mem.indexOfScalar(u8, ".!#$%&'*+-=?^_`{|}~", ch) == null) return false;
    }
    return true;
}

/// Dot-separated LDH labels (RFC 1035), at most 253 octets.
pub fn isDomain(s: []const u8) bool {
    if (s.len == 0 or s.len > 253) return false;
    var labels = std.mem.splitScalar(u8, s, '.');
    while (labels.next()) |label| {
        if (label.len == 0 or label.len > 63) return false;
        if (label[0] == '-' or label[label.len - 1] == '-') return false;
        for (label) |ch| {
            if (!std.ascii.isAlphanumeric(ch) and ch != '-') return false;
        }
    }
    return true;
}

test "parse accepts common forms" {
    const plain = try parse("<alice@example.com>");
    try std.testing.expectEqualStrings("alice", plain.user);
    try std.testing.expectEqualStrings("example.com", plain.domain);
    try std.testing.expect(plain.tag == null);

    const tagged = try parse("  alice+acme@mail.example.com ");
    try std.testing.expectEqualStrings("alice", tagged.user);
    try std.testing.expectEqualStrings("acme", tagged.tag.?);
    try std.testing.expectEqualStrings("mail.example.com", tagged.domain);

    const with_params = try parse("<bob.smith@example.com> SIZE=1000 BODY=8BITMIME");
    try std.testing.expectEqualStrings("bob.smith", with_params.user);
}

test "parse rejects traversal and malformed input" {
    const bad = [_][]const u8{
        "<../../../../tmp/x@example.com>",
        "<x@../../tmp>",
        "<a/b@example.com>",
        "<a@exa/mple.com>",
        "<a\\b@example.com>",
        "<.hidden@example.com>",
        "<a..b@example.com>",
        "<trailing.@example.com>",
        "<a@example..com>",
        "<a@-example.com>",
        "<a@example.com.>",
        "<a\x00b@example.com>",
        "<a b@example.com>",
        "<\"quoted\"@example.com>",
        "<a@[127.0.0.1]>",
        "<>",
        "<@example.com>",
        "<a@>",
        "",
        "a" ++ "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijkl" ++ "@example.com", // 65-octet local part
    };
    for (bad) |raw| {
        if (parse(raw)) |_| {
            std.debug.print("accepted invalid address: {s}\n", .{raw});
            return error.TestUnexpectedResult;
        } else |_| {}
    }
}

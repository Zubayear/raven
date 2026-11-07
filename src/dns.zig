//! MX lookup (RFC 5321 §5.1) through the system resolver: UDP, retried
//! over TCP when the answer is truncated. Nameservers and answer parsing
//! come from std (`HostName.ResolvConf`, `DnsResponse`, `expand`).
const std = @import("std");
const Io = std.Io;
const net = Io.net;
const HostName = net.HostName;

pub const Mx = struct {
    preference: u16,
    host: []const u8,
};

const type_mx = 15;
const class_in = 1;

/// Mail exchangers for `domain`, most preferred first. A domain without MX
/// records is its own exchanger (implicit MX). `error.NullMx` (RFC 7505)
/// and `error.NoSuchDomain` are permanent; other errors are worth a retry.
/// Strings live in `arena`.
pub fn lookupMx(arena: std.mem.Allocator, io: Io, domain: []const u8) ![]const Mx {
    const rc = try HostName.ResolvConf.init(io);
    var query_buf: [512]u8 = undefined;
    var id: [2]u8 = undefined;
    io.random(&id);
    const query = try writeQuery(&query_buf, domain, id);

    for (rc.nameservers()) |*server| {
        const reply = exchange(arena, io, server, query, rc.timeout_seconds) catch continue;
        // SERVFAIL and friends: try the next nameserver.
        const rcode = reply[3] & 0x0f;
        if (rcode != 0 and rcode != 3) continue;
        return parseMx(arena, reply, domain);
    }
    return error.NameServerFailure;
}

/// A query for the MX records of `domain` (RFC 1035 §4.1).
fn writeQuery(buf: []u8, domain: []const u8, id: [2]u8) ![]const u8 {
    const name = std.mem.trimEnd(u8, domain, ".");
    if (name.len == 0 or name.len > 253 or buf.len < 12 + name.len + 2 + 4) return error.InvalidDomain;
    @memset(buf[0..12], 0);
    buf[0..2].* = id;
    buf[2] = 0x01; // RD: recursion desired
    buf[5] = 1; // one question
    var pos: usize = 12;
    var labels = std.mem.splitScalar(u8, name, '.');
    while (labels.next()) |label| {
        if (label.len == 0 or label.len > 63) return error.InvalidDomain;
        buf[pos] = @intCast(label.len);
        @memcpy(buf[pos + 1 ..][0..label.len], label);
        pos += 1 + label.len;
    }
    buf[pos] = 0;
    std.mem.writeInt(u16, buf[pos + 1 ..][0..2], type_mx, .big);
    std.mem.writeInt(u16, buf[pos + 3 ..][0..2], class_in, .big);
    return buf[0 .. pos + 5];
}

/// Sends `query` to `server` over UDP and returns the matching answer,
/// switching to TCP if the server says the UDP answer was truncated.
fn exchange(arena: std.mem.Allocator, io: Io, server: *const net.IpAddress, query: []const u8, timeout_seconds: u32) ![]const u8 {
    const timeout: Io.Timeout = .{ .duration = .{ .raw = .fromSeconds(timeout_seconds), .clock = .boot } };
    const local: net.IpAddress = switch (server.*) {
        .ip4 => .{ .ip4 = .unspecified(0) },
        .ip6 => .{ .ip6 = .unspecified(0) },
    };
    const socket = try local.bind(io, .{ .mode = .dgram });
    defer socket.close(io);
    try socket.send(io, server, query);

    const buf = try arena.alloc(u8, 4096);
    while (true) {
        const message = try socket.receiveTimeout(io, buf, timeout.toDeadline(io));
        // Only answers from the server we asked, to our query id.
        if (!message.from.eql(server) or message.data.len < 12 or !std.mem.eql(u8, message.data[0..2], query[0..2])) continue;
        if (message.data[2] & 0x02 == 0) return message.data; // TC bit clear
        return exchangeTcp(arena, io, server, query, timeout);
    }
}

/// DNS over TCP: each message is prefixed with its length (RFC 1035 §4.2.2).
fn exchangeTcp(arena: std.mem.Allocator, io: Io, server: *const net.IpAddress, query: []const u8, timeout: Io.Timeout) ![]const u8 {
    const stream = try server.connect(io, .{ .mode = .stream, .timeout = timeout });
    defer stream.close(io);
    var write_buf: [600]u8 = undefined;
    var writer = stream.writer(io, &write_buf);
    try writer.interface.writeInt(u16, @intCast(query.len), .big);
    try writer.interface.writeAll(query);
    try writer.interface.flush();

    var read_buf: [512]u8 = undefined;
    var reader = stream.reader(io, &read_buf);
    const len = try reader.interface.takeInt(u16, .big);
    const reply = try reader.interface.readAlloc(arena, len);
    if (reply.len < 12 or !std.mem.eql(u8, reply[0..2], query[0..2])) return error.InvalidDnsPacket;
    return reply;
}

fn parseMx(arena: std.mem.Allocator, reply: []const u8, domain: []const u8) ![]const Mx {
    if (reply.len < 12) return error.InvalidDnsPacket;
    if (reply[3] & 0x0f == 3) return error.NoSuchDomain;

    var records = std.ArrayList(Mx).empty;
    // No answers: skip std's parser, which wants bytes after the question.
    var response: HostName.DnsResponse = if (std.mem.readInt(u16, reply[6..8], .big) == 0) .{ .bytes = reply, .bytes_index = 12, .answers_remaining = 0 } else try HostName.DnsResponse.init(reply);
    while (try response.next()) |answer| {
        if (@backingInt(answer.rr) != type_mx or answer.data_len < 3) continue;
        const data = answer.packet[answer.data_off..][0..answer.data_len];
        const preference = std.mem.readInt(u16, data[0..2], .big);
        // An exchange of "." is a null MX: the domain accepts no mail.
        if (data[2] == 0) return error.NullMx;
        var name_buf: [HostName.max_len]u8 = undefined;
        _, const host = try HostName.expand(answer.packet, answer.data_off + 2, &name_buf);
        try records.append(arena, .{ .preference = preference, .host = try arena.dupe(u8, host.bytes) });
    }
    if (records.items.len == 0) {
        // No MX records: the domain itself is the exchanger (implicit MX).
        try records.append(arena, .{ .preference = 0, .host = try arena.dupe(u8, std.mem.trimEnd(u8, domain, ".")) });
    }
    std.sort.pdq(Mx, records.items, {}, struct {
        fn lessThan(_: void, a: Mx, b: Mx) bool {
            return a.preference < b.preference;
        }
    }.lessThan);
    return records.items;
}

/// A canned answer to an MX query for example.com: `rcode`, then the given
/// answer RRs (each already encoded).
fn testReply(buf: []u8, rcode: u8, answers: []const []const u8) []const u8 {
    var query_buf: [64]u8 = undefined;
    const query = writeQuery(&query_buf, "example.com", .{ 0x12, 0x34 }) catch unreachable;
    @memcpy(buf[0..query.len], query);
    buf[2] = 0x81; // QR + RD
    buf[3] = 0x80 | rcode; // RA + rcode
    std.mem.writeInt(u16, buf[6..8], @intCast(answers.len), .big);
    var pos = query.len;
    for (answers) |rr| {
        @memcpy(buf[pos..][0..rr.len], rr);
        pos += rr.len;
    }
    return buf[0..pos];
}

test "MX answers are sorted, decompressed and validated" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    var buf: [256]u8 = undefined;
    // name=ptr(12) type=MX class=IN ttl=60 rdlen pref exchange
    const mx1 = "\xc0\x0c\x00\x0f\x00\x01\x00\x00\x00\x3c\x00\x08\x00\x14\x03mx1\xc0\x0c"; // 20 mx1.example.com (compressed)
    const mx0 = "\xc0\x0c\x00\x0f\x00\x01\x00\x00\x00\x3c\x00\x12\x00\x05\x03mx0\x06backup\x03net\x00"; // 5 mx0.backup.net
    const cname = "\xc0\x0c\x00\x05\x00\x01\x00\x00\x00\x3c\x00\x02\xc0\x0c"; // other record types are skipped
    const records = try parseMx(arena_state.allocator(), testReply(&buf, 0, &.{ cname, mx1, mx0 }), "example.com");
    try std.testing.expectEqual(@as(usize, 2), records.len);
    try std.testing.expectEqual(@as(u16, 5), records[0].preference);
    try std.testing.expectEqualStrings("mx0.backup.net", records[0].host);
    try std.testing.expectEqualStrings("mx1.example.com", records[1].host);
}

test "implicit MX, null MX and NXDOMAIN" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var buf: [256]u8 = undefined;

    const implicit = try parseMx(arena, testReply(&buf, 0, &.{}), "example.com.");
    try std.testing.expectEqual(@as(usize, 1), implicit.len);
    try std.testing.expectEqualStrings("example.com", implicit[0].host);

    const null_mx = "\xc0\x0c\x00\x0f\x00\x01\x00\x00\x00\x3c\x00\x03\x00\x00\x00";
    try std.testing.expectError(error.NullMx, parseMx(arena, testReply(&buf, 0, &.{null_mx}), "example.com"));
    try std.testing.expectError(error.NoSuchDomain, parseMx(arena, testReply(&buf, 3, &.{}), "example.com"));

    // A compression loop must not hang the parser.
    const looping = "\xc0\x0c\x00\x0f\x00\x01\x00\x00\x00\x3c\x00\x04\x00\x0a\xc0\x00";
    try std.testing.expectError(error.InvalidDnsPacket, parseMx(arena, testReply(&buf, 0, &.{looping}), "example.com"));
}

test "queries are well formed" {
    var buf: [64]u8 = undefined;
    const query = try writeQuery(&buf, "mx.example.com.", .{ 1, 2 });
    try std.testing.expectEqualSlices(u8, "\x01\x02\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x02mx\x07example\x03com\x00\x00\x0f\x00\x01", query);
    try std.testing.expectError(error.InvalidDomain, writeQuery(&buf, "a..b", .{ 0, 0 }));
}

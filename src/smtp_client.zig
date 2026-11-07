//! Outbound SMTP (RFC 5321) for the queue runner: tries a domain's mail
//! exchangers in order, upgrades with STARTTLS when offered, and reports a
//! result for every recipient.
const std = @import("std");
const Io = std.Io;
const net = Io.net;
const conn = @import("conn.zig");
const dns = @import("dns.zig");
const tls = @import("tls.zig");

pub const Outcome = enum {
    delivered,
    /// Temporary (4xx or no answer): try again later.
    retry,
    /// Permanent (5xx, null MX, no such domain): bounce.
    failed,
};

pub const Result = struct {
    outcome: Outcome,
    /// The server's reply or what went wrong, for logs and bounces.
    detail: []const u8,
};

pub const Message = struct {
    sender: []const u8,
    recipients: []const []const u8,
    /// The message with CRLF line endings, not yet dot-stuffed.
    data: []const u8,
};

pub const Options = struct {
    /// Our name in EHLO.
    hostname: []const u8,
    port: u16 = 25,
    tls: ?*tls.TlsClient = null,
};

/// Delivers `message` to its recipients, which all live on `domain`.
/// Results line up with `message.recipients`; strings live in `arena`.
pub fn deliver(arena: std.mem.Allocator, io: Io, domain: []const u8, message: Message, options: Options) ![]Result {
    const exchangers = dns.lookupMx(arena, io, domain) catch |err| {
        const permanent = err == error.NullMx or err == error.NoSuchDomain;
        return everyone(arena, message, if (permanent) .failed else .retry, try std.fmt.allocPrint(arena, "{s}: {t}", .{ domain, err }));
    };
    var last_failure: []const u8 = "no mail exchanger";
    for (exchangers) |exchanger| {
        // A failed connection or unusable dialog decides nothing: next exchanger.
        return deliverVia(arena, io, exchanger.host, message, options) catch |err| {
            last_failure = try std.fmt.allocPrint(arena, "{s}: {t}", .{ exchanger.host, err });
            continue;
        };
    }
    return everyone(arena, message, .retry, last_failure);
}

fn everyone(arena: std.mem.Allocator, message: Message, outcome: Outcome, detail: []const u8) ![]Result {
    const results = try arena.alloc(Result, message.recipients.len);
    @memset(results, .{ .outcome = outcome, .detail = detail });
    return results;
}

/// One SMTP transaction with `host`. An error means nothing was decided.
pub fn deliverVia(arena: std.mem.Allocator, io: Io, host: []const u8, message: Message, options: Options) ![]Result {
    const name = try net.HostName.init(host);
    // ponytail: no connect timeout (std 0.17's Io.Threaded panics on one);
    // the OS gives up after a minute or two, and the queue runner delivers
    // concurrently. Add a deadline once std supports it.
    const stream = try name.connect(io, options.port, .{ .mode = .stream });
    defer stream.close(io);

    var read_buf: [4096]u8 = undefined;
    var write_buf: [4096]u8 = undefined;
    // RFC 5321 §4.5.3.2: five minutes for most replies.
    var socket: conn.Socket = .init(io, stream, .fromSeconds(5 * 60), &read_buf, &write_buf);
    var tls_read: [4096]u8 = undefined;
    var tls_write: [4096]u8 = undefined;
    var secure: ?tls.Connection = null;
    defer if (secure) |*t| t.deinit();
    var session: Session = .{ .arena = arena, .host = host, .r = &socket.reader, .w = &socket.writer.interface };

    if ((try session.reply()).code != 220) return error.Rejected;
    var ehlo = try session.command("EHLO {s}", .{options.hostname});
    if (ehlo.code != 250) return error.Rejected;
    if (options.tls) |client| if (ehlo.has("STARTTLS")) {
        if ((try session.command("STARTTLS", .{})).code == 220) {
            secure = try client.connect(&socket, host, &tls_read, &tls_write);
            session.r = &secure.?.reader;
            session.w = &secure.?.writer;
            ehlo = try session.command("EHLO {s}", .{options.hostname});
            if (ehlo.code != 250) return error.Rejected;
        }
    };

    const results = try arena.alloc(Result, message.recipients.len);
    const mail = if (ehlo.has("SIZE"))
        try session.command("MAIL FROM:<{s}> SIZE={d}", .{ message.sender, message.data.len })
    else
        try session.command("MAIL FROM:<{s}>", .{message.sender});
    if (mail.code / 100 != 2) {
        @memset(results, try session.result(mail));
        return results;
    }

    var accepted: usize = 0;
    for (message.recipients, results) |recipient, *result| {
        const rcpt = try session.command("RCPT TO:<{s}>", .{recipient});
        result.* = try session.result(rcpt);
        accepted += @intFromBool(result.outcome == .delivered);
    }
    if (accepted == 0) {
        session.quit();
        return results;
    }

    const data = try session.command("DATA", .{});
    const final = if (data.code != 354) data else final: {
        try writeDotStuffed(session.w, message.data);
        socket.idle_timeout = .fromSeconds(10 * 60); // RFC 5321 §4.5.3.2.6
        break :final try session.reply();
    };
    // Recipients accepted at RCPT share the fate of the whole message.
    for (results) |*result| {
        if (result.outcome == .delivered) result.* = try session.result(final);
    }
    session.quit();
    return results;
}

const Session = struct {
    arena: std.mem.Allocator,
    host: []const u8,
    r: *Io.Reader,
    w: *Io.Writer,

    fn command(s: *Session, comptime fmt: []const u8, args: anytype) !Reply {
        try s.w.print(fmt ++ "\r\n", args);
        return s.reply(); // reading flushes the command first
    }

    fn reply(s: *Session) !Reply {
        return readReply(s.arena, s.r);
    }

    fn quit(s: *Session) void {
        _ = s.command("QUIT", .{}) catch {};
    }

    /// 2xx/3xx delivered, 5xx failed, anything else retried.
    fn result(s: *Session, answer: Reply) !Result {
        return .{
            .outcome = switch (answer.code / 100) {
                2, 3 => .delivered,
                5 => .failed,
                else => .retry,
            },
            .detail = try std.fmt.allocPrint(s.arena, "{s} said: {d} {s}", .{ s.host, answer.code, answer.text }),
        };
    }
};

pub const Reply = struct {
    code: u16,
    /// The text of every line, joined with '\n'.
    text: []const u8,

    /// Whether an EHLO reply lists `extension`.
    fn has(self: Reply, extension: []const u8) bool {
        var lines = std.mem.splitScalar(u8, self.text, '\n');
        while (lines.next()) |line| {
            const keyword = line[0 .. std.mem.indexOfScalar(u8, line, ' ') orelse line.len];
            if (std.ascii.eqlIgnoreCase(keyword, extension)) return true;
        }
        return false;
    }
};

fn readReply(arena: std.mem.Allocator, r: *Io.Reader) !Reply {
    var text = std.ArrayList(u8).empty;
    var code: ?u16 = null;
    while (true) {
        const raw = try r.takeDelimiter('\n') orelse return error.ConnectionClosed;
        const line = std.mem.trimEnd(u8, raw, "\r");
        if (line.len < 3) return error.MalformedReply;
        const this = std.fmt.parseInt(u16, line[0..3], 10) catch return error.MalformedReply;
        if (code != null and code.? != this) return error.MalformedReply;
        code = this;
        const last = line.len == 3 or line[3] == ' ';
        if (!last and line[3] != '-') return error.MalformedReply;
        if (text.items.len != 0) try text.append(arena, '\n');
        if (line.len > 4) try text.appendSlice(arena, line[4..]);
        if (last) return .{ .code = this, .text = text.items };
    }
}

/// Sends the message with leading dots doubled and the final `.` line
/// (RFC 5321 §4.5.2).
fn writeDotStuffed(w: *Io.Writer, data: []const u8) !void {
    var lines = std.mem.splitScalar(u8, data, '\n');
    while (lines.next()) |raw| {
        if (lines.peek() == null and raw.len == 0) break; // data ended with a line break
        const line = std.mem.trimEnd(u8, raw, "\r");
        if (std.mem.startsWith(u8, line, ".")) try w.writeByte('.');
        try w.writeAll(line);
        try w.writeAll("\r\n");
    }
    try w.writeAll(".\r\n");
}

test "replies: single line, multi-line, malformed" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var r: Io.Reader = .fixed("250-mx.example.net hello\r\n250-SIZE 1000\r\n250-starttls\r\n250 8BITMIME\r\n554 no\r\n");
    const ehlo = try readReply(arena, &r);
    try std.testing.expectEqual(@as(u16, 250), ehlo.code);
    try std.testing.expectEqualStrings("mx.example.net hello\nSIZE 1000\nstarttls\n8BITMIME", ehlo.text);
    try std.testing.expect(ehlo.has("SIZE") and ehlo.has("STARTTLS") and !ehlo.has("PIPELINING"));
    try std.testing.expectEqual(@as(u16, 554), (try readReply(arena, &r)).code);
    try std.testing.expectError(error.ConnectionClosed, readReply(arena, &r));

    for ([_][]const u8{ "25\r\n", "abc ok\r\n", "250-a\r\n251 b\r\n", "250xok\r\n" }) |bad| {
        var br: Io.Reader = .fixed(bad);
        try std.testing.expectError(error.MalformedReply, readReply(arena, &br));
    }
}

test "dot-stuffing" {
    var out: Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    try writeDotStuffed(&out.writer, "a\r\n.b\r\n..c\r\n");
    try writeDotStuffed(&out.writer, "no final newline");
    try std.testing.expectEqualStrings("a\r\n..b\r\n...c\r\n.\r\nno final newline\r\n.\r\n", out.written());
}

test "delivers to a second Raven over SMTP, per-recipient results" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const account_index = @import("account_index.zig");
    const Server = @import("server.zig").Server;
    const Storage = @import("storage.zig").Storage;

    // The receiving Raven: example.com with account alice.
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try account_index.writeTestAccounts(allocator, tmp.dir, &.{"alice"}, "secret");
    const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", tmp.sub_path[0..] });
    defer allocator.free(root);
    var catalog = try @import("tenant_index.zig").parseForTest(allocator, "tenant acme example.com\n");
    defer catalog.deinit(allocator);
    var server = Server.init(allocator, .{ .data_dir = root }, &catalog);

    const loopback = try net.IpAddress.parse("127.0.0.1", 0);
    var listener = try loopback.listen(io, .{});
    defer listener.deinit(io);
    var serving = try io.concurrent(conn.Listener(Server).serve, .{ io, &listener, &server, .{
        .max_connections = 4,
        .idle_timeout = .fromSeconds(10),
        .busy_reply = "421 busy\r\n",
        .tls = null,
    } });
    defer serving.cancel(io);

    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const results = try deliverVia(arena_state.allocator(), io, "127.0.0.1", .{
        .sender = "bob@remote.test",
        .recipients = &.{ "alice@example.com", "nobody@example.com", "carol@elsewhere.test" },
        .data = "Subject: hello\r\n\r\n.dotted line\r\n",
    }, .{ .hostname = "sender.test", .port = listener.socket.address.getPort() });

    try std.testing.expectEqual(Outcome.delivered, results[0].outcome);
    try std.testing.expectEqual(Outcome.failed, results[1].outcome);
    try std.testing.expect(std.mem.indexOf(u8, results[1].detail, "550 5.1.1") != null);
    try std.testing.expectEqual(Outcome.failed, results[2].outcome); // the receiver does not relay

    const inbox = try Storage.init(root).maildirPath(allocator, "acme", "example.com", "alice");
    defer allocator.free(inbox);
    const mailbox = try Storage.openMailbox(io, allocator, inbox);
    defer @import("storage.zig").freeMessages(allocator, mailbox.messages);
    try std.testing.expectEqual(@as(usize, 1), mailbox.messages.len);
    const stored = try Storage.readMessage(io, allocator, mailbox.messages[0]);
    defer allocator.free(stored);
    try std.testing.expectStringEndsWith(stored, "Subject: hello\r\n\r\n.dotted line\r\n");
}

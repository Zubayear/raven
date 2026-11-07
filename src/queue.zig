//! The outbound queue runner: delivers queued mail, retries temporary
//! failures with backoff for up to five days, and bounces permanent
//! failures back to the sender as a delivery status notification
//! (RFC 3464).
const std = @import("std");
const Io = std.Io;
const account_index = @import("account_index.zig");
const address = @import("address.zig");
const smtp_client = @import("smtp_client.zig");
const Storage = @import("storage.zig").Storage;
const QueueEntry = @import("storage.zig").QueueEntry;
const TenantCatalog = @import("tenant_index.zig").TenantCatalog;
const TlsClient = @import("tls.zig").TlsClient;
const writeDate = @import("server.zig").writeDate;

const log = std.log.scoped(.queue);

/// After this long, temporary failures are bounced (RFC 5321 §4.5.4.1
/// suggests 4–5 days).
const max_age = 5 * std.time.s_per_day;
/// Entries attempted at the same time.
const max_parallel = 4;

pub const Runner = struct {
    allocator: std.mem.Allocator,
    storage: Storage,
    catalog: *const TenantCatalog,
    /// Our name in EHLO and in bounces.
    hostname: []const u8,
    tls: ?*TlsClient,
    /// Send everything through this host instead of the recipients' MX.
    relay: ?Relay = null,
    interval: Io.Duration = .fromSeconds(5),

    pub const Relay = struct { host: []const u8, port: u16 };

    /// Scans the queue until canceled.
    pub fn run(self: *Runner, io: Io) void {
        while (true) {
            self.runOnce(io) catch |err| switch (err) {
                error.Canceled => return,
                else => log.err("{t}", .{err}),
            };
            io.sleep(self.interval, .boot) catch return;
        }
    }

    /// Attempts every entry that is due, a few at a time.
    pub fn runOnce(self: *Runner, io: Io) !void {
        var arena_state = std.heap.ArenaAllocator.init(self.allocator);
        defer arena_state.deinit();
        const now = nowSeconds(io);
        var batch: Io.Group = .init;
        defer batch.cancel(io);
        var running: usize = 0;
        for (try self.storage.listQueue(io, arena_state.allocator())) |entry| {
            if (entry.next_attempt > now) continue;
            try batch.concurrent(io, attemptTask, .{ self, io, entry });
            running += 1;
            if (running == max_parallel) {
                try batch.await(io);
                running = 0;
            }
        }
        try batch.await(io);
    }

    fn attemptTask(self: *Runner, io: Io, entry: QueueEntry) Io.Cancelable!void {
        self.attempt(io, entry) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            else => log.err("{s}: {t}", .{ entry.id, err }),
        };
    }

    fn attempt(self: *Runner, io: Io, entry: QueueEntry) !void {
        var arena_state = std.heap.ArenaAllocator.init(self.allocator);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        const data = try self.storage.readQueued(io, arena, entry.id);

        var retry = std.ArrayList([]const u8).empty;
        var failed = std.ArrayList(Failure).empty;
        var groups = try groupByDomain(arena, entry.recipients);
        var it = groups.iterator();
        while (it.next()) |group| {
            const message: smtp_client.Message = .{ .sender = entry.sender, .recipients = group.value_ptr.items, .data = data };
            const results = if (self.relay) |relay|
                smtp_client.deliverVia(arena, io, relay.host, message, .{ .hostname = self.hostname, .port = relay.port, .tls = self.tls }) catch |err|
                    try everyone(arena, message.recipients.len, .retry, try std.fmt.allocPrint(arena, "{s}: {t}", .{ relay.host, err }))
            else
                try smtp_client.deliver(arena, io, group.key_ptr.*, message, .{ .hostname = self.hostname, .tls = self.tls });
            // Details are remote replies: escaped, so they can't forge log lines.
            for (message.recipients, results) |recipient, result| switch (result.outcome) {
                .delivered => log.info("{s}: delivered to {s}", .{ entry.id, recipient }),
                .retry => {
                    log.info("{s}: deferred for {s}: {f}", .{ entry.id, recipient, std.zig.fmtString(result.detail) });
                    try retry.append(arena, recipient);
                },
                .failed => {
                    log.info("{s}: failed for {s}: {f}", .{ entry.id, recipient, std.zig.fmtString(result.detail) });
                    try failed.append(arena, .{ .recipient = recipient, .detail = result.detail });
                },
            };
        }

        const now = nowSeconds(io);
        if (retry.items.len != 0 and now -| entry.created >= max_age) {
            for (retry.items) |recipient| try failed.append(arena, .{ .recipient = recipient, .detail = "delivery kept failing for 5 days", .status = "4.4.7" });
            retry.clearRetainingCapacity();
        }
        // Never bounce a bounce (null sender).
        if (failed.items.len != 0 and entry.sender.len != 0) try self.bounce(io, arena, entry, data, failed.items, now);

        if (retry.items.len == 0) return self.storage.removeQueued(io, self.allocator, entry.id);
        var next = entry;
        next.recipients = retry.items;
        next.attempts += 1;
        next.next_attempt = now + backoff(next.attempts);
        try self.storage.rescheduleQueued(io, self.allocator, next);
    }

    /// Returns failures to the sender: into their mailbox when they are
    /// local, through the queue (with the null sender) otherwise.
    fn bounce(self: *Runner, io: Io, arena: std.mem.Allocator, entry: QueueEntry, original: []const u8, failures: []const Failure, now: u64) !void {
        const dsn = try buildDsn(arena, io, self.hostname, entry, original, failures, now);
        const sender = address.parse(entry.sender) catch return;
        if (account_index.resolveMailbox(self.allocator, io, self.storage, self.catalog, sender)) |owner| {
            defer owner.deinit(self.allocator);
            self.allocator.free(try self.storage.deliver(io, self.allocator, owner.tenant, owner.domain, owner.user, "Return-Path: <>\r\n", dsn));
        } else |_| {
            self.allocator.free(try self.storage.enqueue(io, self.allocator, "", &.{entry.sender}, "", dsn));
        }
    }
};

const Failure = struct {
    recipient: []const u8,
    detail: []const u8,
    /// RFC 3463 status; taken from the detail when it has one.
    status: ?[]const u8 = null,
};

/// Seconds to wait before attempt number `attempts` + 1.
fn backoff(attempts: u32) u64 {
    const schedule = [_]u64{ 60, 5 * 60, 15 * 60, 30 * 60, 3600, 2 * 3600, 4 * 3600 };
    return if (attempts >= 1 and attempts <= schedule.len) schedule[attempts - 1] else 8 * 3600;
}

fn groupByDomain(arena: std.mem.Allocator, recipients: []const []const u8) !std.StringArrayHashMapUnmanaged(std.ArrayList([]const u8)) {
    var groups: std.StringArrayHashMapUnmanaged(std.ArrayList([]const u8)) = .empty;
    for (recipients) |recipient| {
        const at = std.mem.lastIndexOfScalar(u8, recipient, '@') orelse continue;
        const domain = try std.ascii.allocLowerString(arena, recipient[at + 1 ..]);
        const group = try groups.getOrPut(arena, domain);
        if (!group.found_existing) group.value_ptr.* = .empty;
        try group.value_ptr.append(arena, recipient);
    }
    return groups;
}

fn everyone(arena: std.mem.Allocator, count: usize, outcome: smtp_client.Outcome, detail: []const u8) ![]smtp_client.Result {
    const results = try arena.alloc(smtp_client.Result, count);
    @memset(results, .{ .outcome = outcome, .detail = detail });
    return results;
}

fn nowSeconds(io: Io) u64 {
    return @intCast(@divFloor(Io.Clock.real.now(io).nanoseconds, std.time.ns_per_s));
}

/// The first `d.d.d` enhanced status code in `detail`, if any.
fn statusOf(detail: []const u8) ?[]const u8 {
    var words = std.mem.tokenizeAny(u8, detail, " \n");
    while (words.next()) |word| if (isStatus(word)) return word;
    return null;
}

fn isStatus(word: []const u8) bool {
    if (word.len == 0 or (word[0] != '4' and word[0] != '5')) return false;
    var parts = std.mem.splitScalar(u8, word, '.');
    var count: usize = 0;
    while (parts.next()) |part| : (count += 1) {
        if (part.len == 0 or part.len > 3) return false;
        for (part) |ch| if (!std.ascii.isDigit(ch)) return false;
    }
    return count == 3;
}

/// A multipart/report delivery status notification (RFC 3464).
fn buildDsn(arena: std.mem.Allocator, io: Io, hostname: []const u8, entry: QueueEntry, original: []const u8, failures: []const Failure, now: u64) ![]const u8 {
    var random: [8]u8 = undefined;
    io.random(&random);
    const token = std.fmt.bytesToHex(random, .lower);
    const headers = original[0..if (std.mem.indexOf(u8, original, "\r\n\r\n")) |i| i + 2 else original.len];

    var out: Io.Writer.Allocating = .init(arena);
    const w = &out.writer;
    try w.print("From: Mail Delivery System <MAILER-DAEMON@{s}>\r\nTo: <{s}>\r\n", .{ hostname, entry.sender });
    try w.writeAll("Subject: Undelivered Mail Returned to Sender\r\nDate: ");
    try writeDate(w, now);
    try w.print("\r\nMessage-ID: <{s}@{s}>\r\nAuto-Submitted: auto-replied\r\nMIME-Version: 1.0\r\n", .{ &token, hostname });
    try w.print("Content-Type: multipart/report; report-type=delivery-status; boundary=\"{s}\"\r\n\r\n", .{&token});

    try w.print("--{s}\r\nContent-Type: text/plain; charset=us-ascii\r\n\r\n", .{&token});
    try w.print("This is the mail system at {s}.\r\nYour message could not be delivered to these recipients:\r\n\r\n", .{hostname});
    for (failures) |failure| try w.print("  <{s}>: {s}\r\n", .{ failure.recipient, oneLine(failure.detail) });

    try w.print("\r\n--{s}\r\nContent-Type: message/delivery-status\r\n\r\nReporting-MTA: dns; {s}\r\nArrival-Date: ", .{ &token, hostname });
    try writeDate(w, entry.created);
    try w.writeAll("\r\n");
    for (failures) |failure| {
        try w.print("\r\nFinal-Recipient: rfc822; {s}\r\nAction: failed\r\nStatus: {s}\r\nDiagnostic-Code: smtp; {s}\r\n", .{
            failure.recipient, failure.status orelse statusOf(failure.detail) orelse "5.0.0", oneLine(failure.detail),
        });
    }

    try w.print("\r\n--{s}\r\nContent-Type: text/rfc822-headers\r\n\r\n{s}\r\n--{s}--\r\n", .{ &token, headers, &token });
    return out.written();
}

/// Replies can span lines; header fields can't.
fn oneLine(text: []const u8) []const u8 {
    return text[0 .. std.mem.indexOfAny(u8, text, "\r\n") orelse text.len];
}

test "backoff schedule" {
    try std.testing.expectEqual(@as(u64, 60), backoff(1));
    try std.testing.expectEqual(@as(u64, 4 * 3600), backoff(7));
    try std.testing.expectEqual(@as(u64, 8 * 3600), backoff(30));
}

test "status codes come from server replies" {
    try std.testing.expectEqualStrings("5.1.1", statusOf("mx.example said: 550 5.1.1 user unknown").?);
    try std.testing.expectEqualStrings("4.2.2", statusOf("452 4.2.2 mailbox full").?);
    try std.testing.expect(statusOf("connection refused") == null);
    try std.testing.expect(statusOf("version 1.2.3") == null);
}

test "recipients are grouped by domain, case-insensitively" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    var groups = try groupByDomain(arena_state.allocator(), &.{ "a@One.test", "b@two.test", "c@one.TEST" });
    try std.testing.expectEqual(@as(usize, 2), groups.count());
    try std.testing.expectEqual(@as(usize, 2), groups.get("one.test").?.items.len);
}

test "delivery status notification" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const entry: QueueEntry = .{ .id = "x", .sender = "alice@example.com", .recipients = &.{}, .created = 1794044147, .next_attempt = 0 };
    const dsn = try buildDsn(arena_state.allocator(), std.testing.io, "mx.example.com", entry, "Subject: hi\r\nTo: bob@remote.test\r\n\r\nbody", &.{
        .{ .recipient = "bob@remote.test", .detail = "mx.remote.test said: 550 5.1.1 no such user\nmore" },
        .{ .recipient = "carol@remote.test", .detail = "delivery kept failing for 5 days", .status = "4.4.7" },
    }, 1794044200);
    for ([_][]const u8{
        "To: <alice@example.com>\r\n",
        "Auto-Submitted: auto-replied\r\n",
        "Content-Type: multipart/report; report-type=delivery-status; boundary=",
        "  <bob@remote.test>: mx.remote.test said: 550 5.1.1 no such user\r\n",
        "Reporting-MTA: dns; mx.example.com\r\nArrival-Date: Sat, 07 Nov 2026 09:35:47 +0000\r\n",
        "Final-Recipient: rfc822; bob@remote.test\r\nAction: failed\r\nStatus: 5.1.1\r\n",
        "Final-Recipient: rfc822; carol@remote.test\r\nAction: failed\r\nStatus: 4.4.7\r\n",
        "Content-Type: text/rfc822-headers\r\n\r\nSubject: hi\r\nTo: bob@remote.test\r\n",
    }) |expected| {
        if (std.mem.indexOf(u8, dsn, expected) == null) {
            std.debug.print("missing {s} in:\n{s}\n", .{ expected, dsn });
            return error.TestExpectedEqual;
        }
    }
    try std.testing.expect(std.mem.indexOf(u8, dsn, "\nmore") == null); // reply lines don't leak into fields
}

/// A scripted remote MTA: answers one session, replying `rcpt_reply` to RCPT.
fn fakeRemote(io: Io, listener: *std.Io.net.Server, rcpt_reply: []const u8) void {
    const stream = listener.accept(io) catch return;
    defer stream.close(io);
    var read_buf: [1024]u8 = undefined;
    var write_buf: [1024]u8 = undefined;
    var reader = stream.reader(io, &read_buf);
    var writer = stream.writer(io, &write_buf);
    const r = &reader.interface;
    const w = &writer.interface;
    w.writeAll("220 fake ESMTP\r\n") catch return;
    w.flush() catch return;
    var in_data = false;
    while (r.takeDelimiter('\n') catch null) |raw| {
        const line = std.mem.trimEnd(u8, raw, "\r");
        const reply = if (in_data) reply: {
            if (!std.mem.eql(u8, line, ".")) continue;
            in_data = false;
            break :reply "250 queued\r\n";
        } else if (std.ascii.startsWithIgnoreCase(line, "EHLO")) "250 fake\r\n" else if (std.ascii.startsWithIgnoreCase(line, "MAIL")) "250 ok\r\n" else if (std.ascii.startsWithIgnoreCase(line, "RCPT")) rcpt_reply else if (std.ascii.startsWithIgnoreCase(line, "DATA")) data: {
            in_data = true;
            break :data "354 go\r\n";
        } else if (std.ascii.startsWithIgnoreCase(line, "QUIT")) "221 bye\r\n" else "500 what\r\n";
        w.writeAll(reply) catch return;
        w.flush() catch return;
        if (std.ascii.startsWithIgnoreCase(line, "QUIT")) return;
    }
}

/// Queues one message from alice@example.com (a local account) to
/// bob@remote.test and runs the queue once against a fake remote.
fn runAgainstFake(allocator: std.mem.Allocator, tmp: *std.testing.TmpDir, rcpt_reply: []const u8) !Storage {
    const io = std.testing.io;
    try account_index.writeTestAccounts(allocator, tmp.dir, &.{"alice"}, "secret");
    const root = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", tmp.sub_path[0..] });
    const storage = Storage.init(root);
    allocator.free(try storage.enqueue(io, allocator, "alice@example.com", &.{"bob@remote.test"}, "Received: x\r\n", "Subject: out\r\n\r\nhi\r\n"));

    var catalog = try @import("tenant_index.zig").parseForTest(allocator, "tenant acme example.com\n");
    defer catalog.deinit(allocator);
    var listener = try (try std.Io.net.IpAddress.parse("127.0.0.1", 0)).listen(io, .{});
    defer listener.deinit(io);
    var remote = try io.concurrent(fakeRemote, .{ io, &listener, rcpt_reply });
    defer remote.cancel(io);

    var runner: Runner = .{ .allocator = allocator, .storage = storage, .catalog = &catalog, .hostname = "mx.example.com", .tls = null, .relay = .{ .host = "127.0.0.1", .port = listener.socket.address.getPort() } };
    try runner.runOnce(io);
    return storage;
}

test "queue runner: success removes the entry" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const storage = try runAgainstFake(allocator, &tmp, "250 ok\r\n");
    defer allocator.free(storage.root_dir);
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    try std.testing.expectEqual(@as(usize, 0), (try storage.listQueue(std.testing.io, arena_state.allocator())).len);
}

test "queue runner: a temporary failure is retried later" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const storage = try runAgainstFake(allocator, &tmp, "451 4.2.1 try later\r\n");
    defer allocator.free(storage.root_dir);
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const entries = try storage.listQueue(std.testing.io, arena_state.allocator());
    try std.testing.expectEqual(@as(usize, 1), entries.len);
    try std.testing.expectEqual(@as(u32, 1), entries[0].attempts);
    try std.testing.expect(entries[0].next_attempt >= nowSeconds(std.testing.io) + 50);
}

test "queue runner: a permanent failure bounces to the sender" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const storage = try runAgainstFake(allocator, &tmp, "550 5.1.1 no such user\r\n");
    defer allocator.free(storage.root_dir);
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    try std.testing.expectEqual(@as(usize, 0), (try storage.listQueue(io, arena_state.allocator())).len);

    const inbox = try storage.maildirPath(allocator, "acme", "example.com", "alice");
    defer allocator.free(inbox);
    const mailbox = try Storage.openMailbox(io, allocator, inbox);
    defer @import("storage.zig").freeMessages(allocator, mailbox.messages);
    try std.testing.expectEqual(@as(usize, 1), mailbox.messages.len);
    const dsn = try Storage.readMessage(io, allocator, mailbox.messages[0]);
    defer allocator.free(dsn);
    try std.testing.expectStringStartsWith(dsn, "Return-Path: <>\r\nFrom: Mail Delivery System <MAILER-DAEMON@mx.example.com>\r\n");
    try std.testing.expect(std.mem.indexOf(u8, dsn, "Final-Recipient: rfc822; bob@remote.test\r\nAction: failed\r\nStatus: 5.1.1\r\n") != null);
}

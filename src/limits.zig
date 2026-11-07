//! Abuse limits per client address: a lockout after repeated failed logins
//! (shared by SMTP and IMAP) and a cap on concurrent connections. IPv6
//! clients count per /64, the block one subscriber usually gets.
const std = @import("std");
const Io = std.Io;
const net = Io.net;

/// IPv4 clients are kept as IPv4-mapped IPv6 addresses, so they match
/// however the socket reported them.
const Key = [16]u8;

const v4_mapped = [12]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };

fn keyOf(ip: net.IpAddress) Key {
    var key: Key = @splat(0);
    switch (ip) {
        .ip4 => |a| {
            key[0..12].* = v4_mapped;
            key[12..16].* = a.bytes;
        },
        .ip6 => |a| {
            // IPv4-mapped clients of a dual-stack socket keep all 128 bits.
            const n: usize = if (std.mem.eql(u8, a.bytes[0..12], &v4_mapped)) 16 else 8;
            @memcpy(key[0..n], a.bytes[0..n]);
        },
    }
    return key;
}

fn seconds(io: Io) i64 {
    return @intCast(@divFloor(Io.Clock.boot.now(io).nanoseconds, std.time.ns_per_s));
}

/// Failed logins per client address: `max_failures` within `window`
/// seconds lock the address out for another `window`.
pub const AuthThrottle = struct {
    allocator: std.mem.Allocator,
    mutex: Io.Mutex = .init,
    entries: std.AutoHashMapUnmanaged(Key, Entry) = .empty,
    /// Pause before answering a failed login, to slow guessing.
    failure_delay: Io.Duration = .fromSeconds(1),

    pub const max_failures = 10;
    pub const window = 15 * 60;
    /// ponytail: past this many addresses with recent failures, new ones go
    /// uncounted (the failure delay still applies); evict LRU if botnets matter.
    const max_entries = 4096;

    const Entry = struct {
        /// When the current count began.
        since: i64,
        failures: u32 = 0,
        locked_until: i64 = 0,
    };

    pub fn init(allocator: std.mem.Allocator) AuthThrottle {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *AuthThrottle) void {
        self.entries.deinit(self.allocator);
    }

    /// Whether logins from `ip` are refused for now.
    pub fn locked(self: *AuthThrottle, io: Io, ip: ?net.IpAddress) bool {
        return self.lockedAt(io, ip, seconds(io));
    }

    /// Counts a failed login from `ip`, then waits `failure_delay`.
    pub fn failed(self: *AuthThrottle, io: Io, ip: ?net.IpAddress) Io.Cancelable!void {
        self.failedAt(io, ip, seconds(io));
        return io.sleep(self.failure_delay, .boot);
    }

    fn lockedAt(self: *AuthThrottle, io: Io, ip: ?net.IpAddress, now: i64) bool {
        const addr = ip orelse return false;
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        const entry = self.entries.get(keyOf(addr)) orelse return false;
        return now < entry.locked_until;
    }

    fn failedAt(self: *AuthThrottle, io: Io, ip: ?net.IpAddress, now: i64) void {
        const addr = ip orelse return;
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        if (self.entries.count() >= max_entries) {
            // Forget addresses whose count and lockout have both run out.
            var it = self.entries.iterator();
            while (it.next()) |e| {
                if (now - e.value_ptr.since >= window and now >= e.value_ptr.locked_until) self.entries.removeByPtr(e.key_ptr);
            }
            if (self.entries.count() >= max_entries) return;
        }
        const gop = self.entries.getOrPut(self.allocator, keyOf(addr)) catch return;
        if (!gop.found_existing) gop.value_ptr.* = .{ .since = now };
        const entry = gop.value_ptr;
        if (now - entry.since >= window) entry.* = .{ .since = now, .locked_until = entry.locked_until };
        entry.failures += 1;
        if (entry.failures >= max_failures) entry.locked_until = now + window;
    }
};

/// Open connections per client address.
pub const ConnectionCounts = struct {
    mutex: Io.Mutex = .init,
    counts: std.AutoHashMapUnmanaged(Key, u32) = .empty,

    pub fn deinit(self: *ConnectionCounts, allocator: std.mem.Allocator) void {
        self.counts.deinit(allocator);
    }

    /// Counts a connection from `ip` unless `limit` are open already.
    pub fn acquire(self: *ConnectionCounts, io: Io, allocator: std.mem.Allocator, ip: ?net.IpAddress, limit: u32) bool {
        const addr = ip orelse return true;
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        const gop = self.counts.getOrPut(allocator, keyOf(addr)) catch return false;
        if (!gop.found_existing) gop.value_ptr.* = 0;
        if (gop.value_ptr.* >= limit) return false;
        gop.value_ptr.* += 1;
        return true;
    }

    pub fn release(self: *ConnectionCounts, io: Io, ip: ?net.IpAddress) void {
        const addr = ip orelse return;
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        const key = keyOf(addr);
        const count = self.counts.getPtr(key) orelse return;
        count.* -= 1;
        if (count.* == 0) _ = self.counts.remove(key);
    }
};

test "ten failures within the window lock an address out for another window" {
    const io = std.testing.io;
    var throttle: AuthThrottle = .init(std.testing.allocator);
    defer throttle.deinit();
    const ip = try net.IpAddress.parse("192.0.2.7", 25);

    for (0..AuthThrottle.max_failures - 1) |i| throttle.failedAt(io, ip, 100 + @as(i64, @intCast(i)));
    try std.testing.expect(!throttle.lockedAt(io, ip, 200));
    throttle.failedAt(io, ip, 900); // the tenth, inside the window that began at 100
    try std.testing.expect(throttle.lockedAt(io, ip, 900));
    try std.testing.expect(throttle.lockedAt(io, ip, 900 + AuthThrottle.window - 1));
    try std.testing.expect(!throttle.lockedAt(io, ip, 900 + AuthThrottle.window));

    try std.testing.expect(!throttle.lockedAt(io, try net.IpAddress.parse("192.0.2.8", 25), 900));
    try std.testing.expect(!throttle.lockedAt(io, null, 900));
    throttle.failedAt(io, null, 900); // unknown peers are never counted
}

test "failures outside the window start a new count" {
    const io = std.testing.io;
    var throttle: AuthThrottle = .init(std.testing.allocator);
    defer throttle.deinit();
    const ip = try net.IpAddress.parse("192.0.2.7", 25);

    for (0..AuthThrottle.max_failures - 1) |_| throttle.failedAt(io, ip, 0);
    throttle.failedAt(io, ip, AuthThrottle.window);
    try std.testing.expect(!throttle.lockedAt(io, ip, AuthThrottle.window));
    for (0..AuthThrottle.max_failures - 2) |_| throttle.failedAt(io, ip, AuthThrottle.window + 1);
    try std.testing.expect(!throttle.lockedAt(io, ip, AuthThrottle.window + 1));
    throttle.failedAt(io, ip, AuthThrottle.window + 2);
    try std.testing.expect(throttle.lockedAt(io, ip, AuthThrottle.window + 2));
}

test "IPv6 clients count per /64 and IPv4 matches its mapped form" {
    const a = keyOf(try net.IpAddress.parse("2001:db8:1:2::1", 0));
    try std.testing.expectEqual(a, keyOf(try net.IpAddress.parse("2001:db8:1:2:ffff::9", 0)));
    try std.testing.expect(!std.mem.eql(u8, &a, &keyOf(try net.IpAddress.parse("2001:db8:1:3::1", 0))));

    const v4 = keyOf(try net.IpAddress.parse("192.0.2.1", 0));
    try std.testing.expectEqual(v4, keyOf(.{ .ip6 = .{ .bytes = v4_mapped ++ [4]u8{ 192, 0, 2, 1 }, .port = 0 } }));
    try std.testing.expect(!std.mem.eql(u8, &v4, &keyOf(.{ .ip6 = .{ .bytes = v4_mapped ++ [4]u8{ 192, 0, 2, 2 }, .port = 0 } })));
}

test "connections are capped per address" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    var counts: ConnectionCounts = .{};
    defer counts.deinit(allocator);
    const ip = try net.IpAddress.parse("192.0.2.7", 1000);
    const other = try net.IpAddress.parse("192.0.2.8", 1000);

    try std.testing.expect(counts.acquire(io, allocator, ip, 2));
    try std.testing.expect(counts.acquire(io, allocator, try net.IpAddress.parse("192.0.2.7", 1001), 2));
    try std.testing.expect(!counts.acquire(io, allocator, ip, 2));
    try std.testing.expect(counts.acquire(io, allocator, other, 2));
    try std.testing.expect(counts.acquire(io, allocator, null, 2));
    counts.release(io, ip);
    try std.testing.expect(counts.acquire(io, allocator, ip, 2));
    for (0..2) |_| counts.release(io, ip);
    counts.release(io, other);
    try std.testing.expectEqual(0, counts.counts.count());
}

//! DKIM signing (RFC 6376): rsa-sha256 with relaxed/relaxed
//! canonicalization. A domain's keys live in
//! `tenants/<tenant>/domains/<domain>/dkim/<selector>.pem`; the
//! alphabetically last one signs, so rotating means adding a new file and
//! removing the old one once its DNS record is gone.
const std = @import("std");
const Io = std.Io;
const c = @import("openssl");
const address = @import("address.zig");

/// Header fields signed when present (RFC 6376 §5.4.1).
const signed_fields = [_][]const u8{ "From", "Reply-To", "Subject", "Date", "To", "Cc", "Message-ID", "In-Reply-To", "References", "MIME-Version", "Content-Type", "Content-Transfer-Encoding" };

/// OpenSSL caps RSA moduli at 16384 bits.
const max_signature = 2048;

pub const Key = struct {
    pkey: *c.EVP_PKEY,
    selector: []u8,

    pub fn deinit(self: Key, allocator: std.mem.Allocator) void {
        c.EVP_PKEY_free(self.pkey);
        allocator.free(self.selector);
    }
};

/// The signing key in `key_dir`, or null if the domain has none.
pub fn loadKey(allocator: std.mem.Allocator, io: Io, key_dir: []const u8) !?Key {
    var dir = Io.Dir.cwd().openDir(io, key_dir, .{ .iterate = true }) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    defer dir.close(io);

    var name_buf: [std.fs.max_name_bytes]u8 = undefined;
    var newest: ?[]const u8 = null;
    var it = dir.iterate();
    while (try it.next(io)) |entry| {
        // Any kind: Kubernetes secret mounts are symlinks.
        if (!std.mem.endsWith(u8, entry.name, ".pem")) continue;
        // The selector goes into the header and DNS: LDH labels only.
        if (!address.isDomain(entry.name[0 .. entry.name.len - ".pem".len])) continue;
        if (newest != null and std.mem.order(u8, entry.name, newest.?) != .gt) continue;
        @memcpy(name_buf[0..entry.name.len], entry.name);
        newest = name_buf[0..entry.name.len];
    }
    const name = newest orelse return null;

    const pem = try dir.readFileAlloc(io, name, allocator, .limited(64 * 1024));
    defer {
        std.crypto.secureZero(u8, pem);
        allocator.free(pem);
    }
    const bio = c.BIO_new_mem_buf(pem.ptr, @intCast(pem.len)) orelse return error.OutOfMemory;
    defer _ = c.BIO_free(bio);
    // An empty passphrase: an encrypted key fails instead of prompting on the TTY.
    const no_passphrase: [*:0]const u8 = "";
    const pkey = c.PEM_read_bio_PrivateKey(bio, null, null, @ptrCast(@constCast(no_passphrase))) orelse return error.DkimKeyInvalid;
    errdefer c.EVP_PKEY_free(pkey);
    // RFC 8301: verifiers reject RSA keys under 1024 bits.
    if (c.EVP_PKEY_is_a(pkey, "RSA") != 1 or c.EVP_PKEY_get_bits(pkey) < 1024) return error.DkimKeyUnsupported;
    return .{ .pkey = pkey, .selector = try allocator.dupe(u8, name[0 .. name.len - ".pem".len]) };
}

/// The folded `DKIM-Signature:` header field (with its CRLF) that signs
/// `message` for `domain`.
pub fn sign(allocator: std.mem.Allocator, key: Key, domain: []const u8, message: []const u8, timestamp: u64) ![]u8 {
    const split = std.mem.indexOf(u8, message, "\r\n\r\n");
    const header = if (split) |i| message[0 .. i + 2] else message;
    const body = if (split) |i| message[i + 4 ..] else "";
    if (lastField(header, "From") == null) return error.MissingFrom;

    var canonical: Io.Writer.Allocating = .init(allocator);
    defer canonical.deinit();
    try canonicalizeBody(&canonical.writer, body);
    var body_hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(canonical.written(), &body_hash, .{});
    var bh_buf: [44]u8 = undefined;
    const bh = std.base64.standard.Encoder.encode(&bh_buf, &body_hash);

    // Signed: the last instance of each field (verifiers pick instances
    // bottom-up), then this header with b= empty and no CRLF (§3.7).
    canonical.clearRetainingCapacity();
    var names: Io.Writer.Allocating = .init(allocator);
    defer names.deinit();
    for (signed_fields) |name| {
        const field = lastField(header, name) orelse continue;
        try canonicalizeHeader(&canonical.writer, field);
        try canonical.writer.writeAll("\r\n");
        if (names.written().len != 0) try names.writer.writeByte(':');
        for (name) |ch| try names.writer.writeByte(std.ascii.toLower(ch));
    }
    var out: Io.Writer.Allocating = .init(allocator);
    errdefer out.deinit();
    try out.writer.print("DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d={s}; s={s};\r\n\tt={d}; h={s};\r\n\tbh={s};\r\n\tb=", .{ domain, key.selector, timestamp, names.written(), bh });
    try canonicalizeHeader(&canonical.writer, out.written());

    const ctx = c.EVP_MD_CTX_new() orelse return error.OutOfMemory;
    defer c.EVP_MD_CTX_free(ctx);
    var signature: [max_signature]u8 = undefined;
    var len: usize = signature.len;
    if (c.EVP_DigestSignInit(ctx, null, c.EVP_sha256(), null, key.pkey) != 1 or
        c.EVP_DigestSign(ctx, &signature, &len, canonical.written().ptr, canonical.written().len) != 1) return error.DkimSignFailed;

    // Folding whitespace inside b= is ignored by verifiers.
    var b64_buf: [std.base64.standard.Encoder.calcSize(max_signature)]u8 = undefined;
    var rest = std.base64.standard.Encoder.encode(&b64_buf, signature[0..len]);
    while (rest.len > 72) : (rest = rest[72..]) try out.writer.print("{s}\r\n\t", .{rest[0..72]});
    try out.writer.print("{s}\r\n", .{rest});
    return out.toOwnedSlice();
}

/// The last instance of header field `name`, continuation lines included.
fn lastField(header: []const u8, name: []const u8) ?[]const u8 {
    var found: ?[]const u8 = null;
    var pos: usize = 0;
    while (pos < header.len) {
        var end = std.mem.indexOfPos(u8, header, pos, "\r\n") orelse header.len;
        while (end + 2 < header.len and (header[end + 2] == ' ' or header[end + 2] == '\t')) {
            end = std.mem.indexOfPos(u8, header, end + 2, "\r\n") orelse header.len;
        }
        const field = header[pos..end];
        const colon = std.mem.indexOfScalar(u8, field, ':') orelse field.len;
        if (std.ascii.eqlIgnoreCase(std.mem.trimEnd(u8, field[0..colon], " \t"), name)) found = field;
        pos = end + 2;
    }
    return found;
}

/// Relaxed header canonicalization (RFC 6376 §3.4.2).
fn canonicalizeHeader(w: *Io.Writer, field: []const u8) !void {
    const colon = std.mem.indexOfScalar(u8, field, ':') orelse return error.MalformedHeader;
    for (std.mem.trim(u8, field[0..colon], " \t")) |ch| try w.writeByte(std.ascii.toLower(ch));
    try w.writeByte(':');
    try writeCollapsed(w, field[colon + 1 ..], false);
}

/// Relaxed body canonicalization (RFC 6376 §3.4.4): no trailing empty lines,
/// and a non-empty body ends with CRLF.
fn canonicalizeBody(w: *Io.Writer, body: []const u8) !void {
    var empty_lines: usize = 0;
    var lines = std.mem.splitSequence(u8, body, "\r\n");
    while (lines.next()) |line| {
        if (lines.peek() == null and line.len == 0) break; // past the final CRLF
        if (std.mem.trimEnd(u8, line, " \t").len == 0) {
            empty_lines += 1;
            continue;
        }
        for (0..empty_lines) |_| try w.writeAll("\r\n");
        empty_lines = 0;
        try writeCollapsed(w, line, true);
        try w.writeAll("\r\n");
    }
}

/// Writes `text` unfolded, with whitespace runs as one space and none at
/// the end; leading whitespace survives (as one space) only if `keep_leading`.
fn writeCollapsed(w: *Io.Writer, text: []const u8, keep_leading: bool) !void {
    var space = false;
    var wrote = keep_leading;
    var pieces = std.mem.splitSequence(u8, text, "\r\n");
    while (pieces.next()) |piece| {
        for (piece) |ch| {
            if (ch == ' ' or ch == '\t') {
                space = wrote;
                continue;
            }
            if (space) try w.writeByte(' ');
            space = false;
            wrote = true;
            try w.writeByte(ch);
        }
    }
}

test "relaxed canonicalization (RFC 6376 §3.4.5 example)" {
    var out: Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    try canonicalizeHeader(&out.writer, "A: X");
    try out.writer.writeAll("\r\n");
    try canonicalizeHeader(&out.writer, "B : Y\t\r\n\tZ  ");
    try out.writer.writeAll("\r\n");
    try std.testing.expectEqualStrings("a:X\r\nb:Y Z\r\n", out.written());

    out.clearRetainingCapacity();
    try canonicalizeBody(&out.writer, " C \r\nD \t E\r\n\r\n\r\n");
    try std.testing.expectEqualStrings(" C\r\nD E\r\n", out.written());

    out.clearRetainingCapacity();
    try canonicalizeBody(&out.writer, "");
    try canonicalizeBody(&out.writer, " \t\r\n\r\n");
    try std.testing.expectEqualStrings("", out.written());
    try canonicalizeBody(&out.writer, "a\r\n \r\nb");
    try std.testing.expectEqualStrings("a\r\n\r\nb\r\n", out.written());
}

test "the last instance of a field is signed" {
    const header = "From: a@x\r\nSubject: one\r\nSubject: two\r\n  folded\r\nTo: b@y\r\n";
    try std.testing.expectEqualStrings("Subject: two\r\n  folded", lastField(header, "subject").?);
    try std.testing.expect(lastField(header, "Cc") == null);
}

test "signatures verify with the public key" {
    const allocator = std.testing.allocator;
    const key: Key = .{ .pkey = c.EVP_PKEY_Q_keygen(null, null, "RSA", @as(usize, 2048)) orelse return error.KeyGenFailed, .selector = try allocator.dupe(u8, "test") };
    defer key.deinit(allocator);

    const message = "From: Alice <alice@example.com>\r\nTo: bob@remote.test\r\nSubject: hi\r\n\r\nhello  world \r\n\r\n";
    try std.testing.expectError(error.MissingFrom, sign(allocator, key, "example.com", message[33..], 0));
    const header = try sign(allocator, key, "example.com", message, 1794044147);
    defer allocator.free(header);

    var expected_hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("hello world\r\n", &expected_hash, .{});
    var bh_buf: [44]u8 = undefined;
    const prefix = try std.fmt.allocPrint(allocator, "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=test;\r\n\tt=1794044147; h=from:subject:to;\r\n\tbh={s};\r\n\tb=", .{std.base64.standard.Encoder.encode(&bh_buf, &expected_hash)});
    defer allocator.free(prefix);
    try std.testing.expectStringStartsWith(header, prefix);

    // Verify the way a receiver would: signed fields in h= order, then the
    // signature header with b= emptied.
    var data: Io.Writer.Allocating = .init(allocator);
    defer data.deinit();
    try data.writer.writeAll("from:Alice <alice@example.com>\r\nsubject:hi\r\nto:bob@remote.test\r\n");
    try canonicalizeHeader(&data.writer, prefix);
    var b64: std.ArrayList(u8) = .empty;
    defer b64.deinit(allocator);
    for (header[prefix.len..]) |ch| if (!std.ascii.isWhitespace(ch)) try b64.append(allocator, ch);
    var signature: [max_signature]u8 = undefined;
    const len = try std.base64.standard.Decoder.calcSizeForSlice(b64.items);
    try std.base64.standard.Decoder.decode(&signature, b64.items);

    const ctx = c.EVP_MD_CTX_new() orelse return error.OutOfMemory;
    defer c.EVP_MD_CTX_free(ctx);
    try std.testing.expectEqual(1, c.EVP_DigestVerifyInit(ctx, null, c.EVP_sha256(), null, key.pkey));
    try std.testing.expectEqual(1, c.EVP_DigestVerify(ctx, &signature, len, data.written().ptr, data.written().len));
}

const std = @import("std");
const Io = std.Io;
const c = @import("openssl");

pub const TlsServer = struct {
    ctx: *c.SSL_CTX,

    pub fn init(allocator: std.mem.Allocator, cert_file: []const u8, key_file: []const u8) !TlsServer {
        const ctx = c.SSL_CTX_new(c.TLS_server_method()) orelse return sslError("SSL_CTX_new");
        errdefer c.SSL_CTX_free(ctx);

        if (c.SSL_CTX_set_min_proto_version(ctx, c.TLS1_2_VERSION) != 1) return sslError("set min TLS version");

        const cert_z = try allocator.dupeSentinel(u8, cert_file, 0);
        defer allocator.free(cert_z);
        if (c.SSL_CTX_use_certificate_chain_file(ctx, cert_z.ptr) != 1) return sslError("load certificate");

        const key_z = try allocator.dupeSentinel(u8, key_file, 0);
        defer allocator.free(key_z);
        if (c.SSL_CTX_use_PrivateKey_file(ctx, key_z.ptr, c.SSL_FILETYPE_PEM) != 1) return sslError("load private key");
        if (c.SSL_CTX_check_private_key(ctx) != 1) return sslError("certificate/key mismatch");

        return .{ .ctx = ctx };
    }

    pub fn deinit(self: *TlsServer) void {
        c.SSL_CTX_free(self.ctx);
        self.* = undefined;
    }

    /// Performs the server-side handshake on `fd`. The returned connection
    /// must not be moved once its `reader`/`writer` are in use.
    pub fn accept(self: *TlsServer, fd: std.posix.fd_t, read_buffer: []u8, write_buffer: []u8) !Connection {
        const ssl = c.SSL_new(self.ctx) orelse return error.TlsHandshakeFailed;
        errdefer c.SSL_free(ssl);

        if (c.SSL_set_fd(ssl, fd) != 1) return error.TlsHandshakeFailed;
        if (c.SSL_accept(ssl) != 1) return error.TlsHandshakeFailed;

        return .{
            .ssl = ssl,
            .reader = .{ .vtable = &.{ .stream = stream }, .buffer = read_buffer, .seek = 0, .end = 0 },
            .writer = .{ .vtable = &.{ .drain = drain }, .buffer = write_buffer },
        };
    }
};

/// A TLS session over a socket owned by the caller; `deinit` does not close
/// the socket.
pub const Connection = struct {
    ssl: *c.SSL,
    reader: Io.Reader,
    writer: Io.Writer,

    pub fn deinit(self: *Connection) void {
        _ = c.SSL_shutdown(self.ssl);
        c.SSL_free(self.ssl);
        self.* = undefined;
    }

    fn writeAll(self: *Connection, bytes: []const u8) Io.Writer.Error!void {
        var rest = bytes;
        while (rest.len > 0) {
            const n = c.SSL_write(self.ssl, rest.ptr, @intCast(@min(rest.len, std.math.maxInt(c_int))));
            if (n <= 0) return error.WriteFailed;
            rest = rest[@intCast(n)..];
        }
    }
};

fn stream(r: *Io.Reader, w: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
    const conn: *Connection = @alignCast(@fieldParentPtr("reader", r));
    const dest = limit.slice(try w.writableSliceGreedy(1));
    const n = c.SSL_read(conn.ssl, dest.ptr, @intCast(@min(dest.len, std.math.maxInt(c_int))));
    if (n <= 0) return switch (c.SSL_get_error(conn.ssl, n)) {
        c.SSL_ERROR_ZERO_RETURN => error.EndOfStream,
        else => error.ReadFailed,
    };
    w.advance(@intCast(n));
    return @intCast(n);
}

fn drain(w: *Io.Writer, data: []const []const u8, splat: usize) Io.Writer.Error!usize {
    const conn: *Connection = @alignCast(@fieldParentPtr("writer", w));
    try conn.writeAll(w.buffered());
    w.end = 0;

    var written: usize = 0;
    for (data[0 .. data.len - 1]) |bytes| {
        try conn.writeAll(bytes);
        written += bytes.len;
    }
    for (0..splat) |_| {
        try conn.writeAll(data[data.len - 1]);
        written += data[data.len - 1].len;
    }
    return written;
}

fn sslError(what: []const u8) error{TlsInitFailed} {
    var buf: [256]u8 = undefined;
    c.ERR_error_string_n(c.ERR_get_error(), &buf, buf.len);
    std.debug.print("tls: {s} failed: {s}\n", .{ what, std.mem.sliceTo(&buf, 0) });
    return error.TlsInitFailed;
}

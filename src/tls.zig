const std = @import("std");

const c = @cImport({
    @cInclude("openssl/err.h");
    @cInclude("openssl/pem.h");
    @cInclude("openssl/ssl.h");
});

pub const TlsServer = struct {
    allocator: std.mem.Allocator,
    ctx: *c.SSL_CTX,
    vtable: std.Io.VTable,

    pub fn init(allocator: std.mem.Allocator, cert_file: []const u8, key_file: []const u8) !TlsServer {
        const ctx = c.SSL_CTX_new(c.TLS_server_method()) orelse return error.TlsInitFailed;
        errdefer c.SSL_CTX_free(ctx);

        _ = c.SSL_CTX_set_min_proto_version(ctx, c.TLS1_2_VERSION);

        try useCertificateFile(ctx, allocator, cert_file);
        try usePrivateKeyFile(ctx, allocator, key_file);
        if (c.SSL_CTX_check_private_key(ctx) != 1) return error.TlsInitFailed;

        var vtable = std.Options.debug_io.vtable.*;
        vtable.netRead = netRead;
        vtable.netWrite = netWrite;
        vtable.netClose = netClose;
        vtable.netShutdown = netShutdown;

        return .{
            .allocator = allocator,
            .ctx = ctx,
            .vtable = vtable,
        };
    }

    pub fn deinit(self: *TlsServer) void {
        c.SSL_CTX_free(self.ctx);
        self.* = undefined;
    }

    pub fn accept(self: *TlsServer, socket_handle: std.posix.fd_t) !TlsConnection {
        const ssl = c.SSL_new(self.ctx) orelse return error.TlsHandshakeFailed;
        errdefer c.SSL_free(ssl);

        if (c.SSL_set_fd(ssl, @intCast(socket_handle)) != 1) return error.TlsHandshakeFailed;

        while (true) {
            const rc = c.SSL_accept(ssl);
            if (rc == 1) break;
            const err = c.SSL_get_error(ssl, rc);
            switch (err) {
                c.SSL_ERROR_WANT_READ, c.SSL_ERROR_WANT_WRITE => continue,
                else => return error.TlsHandshakeFailed,
            }
        }

        return .{ .server = self, .ssl = ssl, .socket_handle = socket_handle };
    }
};

pub const TlsConnection = struct {
    server: *TlsServer,
    ssl: ?*c.SSL,
    socket_handle: ?std.posix.fd_t,

    pub fn io(self: *TlsConnection) std.Io {
        return .{ .userdata = self, .vtable = &self.server.vtable };
    }

    pub fn deinit(self: *TlsConnection) void {
        self.close();
        self.* = undefined;
    }

    pub fn close(self: *TlsConnection) void {
        const ssl = self.ssl orelse return;
        self.ssl = null;
        _ = c.SSL_shutdown(ssl);
        if (self.socket_handle) |fd| {
            self.socket_handle = null;
            _ = std.posix.system.close(fd);
        }
        c.SSL_free(ssl);
    }
};

fn useCertificateFile(ctx: *c.SSL_CTX, allocator: std.mem.Allocator, path: []const u8) !void {
    const z = try allocator.dupeZ(u8, path);
    defer allocator.free(z);
    if (c.SSL_CTX_use_certificate_file(ctx, z.ptr, c.SSL_FILETYPE_PEM) != 1) return error.TlsInitFailed;
}

fn usePrivateKeyFile(ctx: *c.SSL_CTX, allocator: std.mem.Allocator, path: []const u8) !void {
    const z = try allocator.dupeZ(u8, path);
    defer allocator.free(z);
    if (c.SSL_CTX_use_PrivateKey_file(ctx, z.ptr, c.SSL_FILETYPE_PEM) != 1) return error.TlsInitFailed;
}

fn netRead(userdata: ?*anyopaque, src: std.Io.net.Socket.Handle, data: [][]u8) std.Io.net.Stream.Reader.Error!usize {
    const conn: *TlsConnection = @ptrCast(@alignCast(userdata));
    _ = src;
    const ssl = conn.ssl orelse return error.ConnectionResetByPeer;

    var total: usize = 0;
    for (data) |buf| {
        if (buf.len == 0) continue;

        while (true) {
            const n = c.SSL_read(ssl, buf.ptr, @intCast(buf.len));
            if (n > 0) {
                total += @intCast(n);
                break;
            }

            const err = c.SSL_get_error(ssl, n);
            switch (err) {
                c.SSL_ERROR_ZERO_RETURN => return total,
                c.SSL_ERROR_WANT_READ, c.SSL_ERROR_WANT_WRITE => continue,
                c.SSL_ERROR_SYSCALL, c.SSL_ERROR_SSL => return error.ConnectionResetByPeer,
                else => return error.ConnectionResetByPeer,
            }
        }
    }

    return total;
}

fn netWrite(userdata: ?*anyopaque, dest: std.Io.net.Socket.Handle, header: []const u8, data: []const []const u8, splat: usize) std.Io.net.Stream.Writer.Error!usize {
    const conn: *TlsConnection = @ptrCast(@alignCast(userdata));
    _ = dest;
    const ssl = conn.ssl orelse return error.Unexpected;

    var total: usize = 0;
    total += try writeChunk(ssl, header);
    if (data.len == 0) return total;

    for (data[0 .. data.len - 1]) |chunk| {
        total += try writeChunk(ssl, chunk);
    }
    const last = data[data.len - 1];
    for (0..splat) |_| {
        total += try writeChunk(ssl, last);
    }

    return total;
}

fn netClose(userdata: ?*anyopaque, handles: []const std.Io.net.Socket.Handle) void {
    const conn: *TlsConnection = @ptrCast(@alignCast(userdata));
    _ = handles;
    conn.close();
}

fn netShutdown(userdata: ?*anyopaque, handle: std.Io.net.Socket.Handle, how: std.Io.net.ShutdownHow) std.Io.net.ShutdownError!void {
    const conn: *TlsConnection = @ptrCast(@alignCast(userdata));
    _ = handle;
    _ = how;
    if (conn.ssl) |ssl| _ = c.SSL_shutdown(ssl);
}

fn writeChunk(ssl: *c.SSL, bytes: []const u8) std.Io.net.Stream.Writer.Error!usize {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const n = c.SSL_write(ssl, bytes[offset..].ptr, @intCast(bytes.len - offset));
        if (n > 0) {
            offset += @intCast(n);
            continue;
        }

        const err = c.SSL_get_error(ssl, n);
        switch (err) {
            c.SSL_ERROR_WANT_READ, c.SSL_ERROR_WANT_WRITE => continue,
            c.SSL_ERROR_SYSCALL, c.SSL_ERROR_SSL => return error.Unexpected,
            else => return error.Unexpected,
        }
    }
    return bytes.len;
}

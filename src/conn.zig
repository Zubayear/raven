//! Accepted connections: the accept loop shared by the SMTP and IMAP
//! listeners, and socket I/O with an idle timeout.
const std = @import("std");
const Io = std.Io;
const net = Io.net;
const tls = @import("tls.zig");
const TlsServer = tls.TlsServer;

pub const Options = struct {
    max_connections: u32,
    /// A session is closed when the peer sends nothing for this long.
    idle_timeout: Io.Duration,
    /// Sent to clients turned away because `max_connections` is reached.
    busy_reply: []const u8,
    /// Enables TLS: STARTTLS, or the whole connection when `implicit_tls`.
    tls: ?*TlsServer,
    implicit_tls: bool = false,
};

/// What a protocol handler talks to. `startTls` upgrades it in place.
pub const Client = struct {
    reader: *Io.Reader,
    writer: *Io.Writer,
    /// True once the connection is encrypted.
    secure: bool = false,
    /// Null in unit tests, which drive handlers over fixed buffers.
    transport: ?*Transport = null,
    /// The peer's address, if known.
    remote: ?net.IpAddress = null,

    pub fn canStartTls(self: Client) bool {
        return !self.secure and self.transport != null and self.transport.?.tls_server != null;
    }

    /// Runs the TLS handshake and switches `reader`/`writer` to it. Plaintext
    /// already buffered is dropped: commands pipelined after STARTTLS must
    /// not run as if they had arrived encrypted (CVE-2011-0411).
    pub fn startTls(self: *Client) !void {
        const t = self.transport.?;
        self.reader.tossBuffered();
        t.tls = try t.tls_server.?.accept(&t.socket, &t.tls_buf, &.{});
        self.reader = &t.tls.?.reader;
        self.writer = &t.tls.?.writer;
        self.secure = true;
    }
};

pub const Transport = struct {
    socket: Socket,
    tls_server: ?*TlsServer,
    tls: ?tls.Connection = null,
    tls_buf: [1024]u8 = undefined,
};

/// A protocol server: `Handler.handleClient(*Handler, Io, *Client)`.
pub fn Listener(comptime Handler: type) type {
    return struct {
        /// Accepts connections until canceled and serves each one
        /// concurrently. Canceling this task cancels every open session.
        pub fn serve(io: Io, listener: *net.Server, handler: *Handler, options: Options) void {
            var sessions: Io.Group = .init;
            defer sessions.cancel(io);
            var active = std.atomic.Value(u32).init(0);

            while (true) {
                const stream = listener.accept(io) catch |err| switch (err) {
                    error.Canceled, error.SocketNotListening => return,
                    else => {
                        std.debug.print("accept error: {}\n", .{err});
                        continue;
                    },
                };
                if (active.fetchAdd(1, .monotonic) >= options.max_connections) {
                    _ = active.fetchSub(1, .monotonic);
                    var writer = stream.writer(io, &.{});
                    writer.interface.writeAll(options.busy_reply) catch {};
                    stream.close(io);
                    continue;
                }
                sessions.concurrent(io, session, .{ io, stream, handler, options, &active }) catch |err| {
                    _ = active.fetchSub(1, .monotonic);
                    stream.close(io);
                    std.debug.print("cannot start session: {}\n", .{err});
                };
            }
        }

        fn session(io: Io, stream: net.Stream, handler: *Handler, options: Options, active: *std.atomic.Value(u32)) void {
            defer {
                stream.close(io);
                _ = active.fetchSub(1, .monotonic);
            }
            var read_buf: [1024]u8 = undefined;
            var transport: Transport = .{
                .socket = .init(io, stream, options.idle_timeout, &read_buf),
                .tls_server = options.tls,
            };
            defer if (transport.tls) |*conn| conn.deinit();
            var client: Client = .{
                .reader = &transport.socket.reader,
                .writer = &transport.socket.writer.interface,
                .transport = &transport,
                .remote = stream.socket.address,
            };

            if (options.implicit_tls) client.startTls() catch |err| {
                std.debug.print("tls handshake failed: {} ({?})\n", .{ err, transport.socket.err });
                return;
            };
            handler.handleClient(io, &client) catch |err| {
                std.debug.print("session ended: {} ({?})\n", .{ err, transport.socket.err });
            };
        }
    };
}

/// Socket I/O through std.Io, so reads time out and every operation is a
/// cancelation point. TLS runs on top of `read` and `writer`.
pub const Socket = struct {
    io: Io,
    stream: net.Stream,
    idle_timeout: Io.Duration,
    reader: Io.Reader,
    writer: net.Stream.Writer,
    /// Transport error behind the last failed read, for diagnostics.
    err: ?anyerror = null,

    /// The returned value must not move once `reader` or `writer` is used.
    pub fn init(io: Io, stream: net.Stream, idle_timeout: Io.Duration, read_buffer: []u8) Socket {
        return .{
            .io = io,
            .stream = stream,
            .idle_timeout = idle_timeout,
            .reader = .{ .vtable = &.{ .stream = streamRead }, .buffer = read_buffer, .seek = 0, .end = 0 },
            .writer = stream.writer(io, &.{}),
        };
    }

    /// Reads at least one byte, or returns 0 at end of stream. Fails with
    /// `error.Timeout` if nothing arrives within `idle_timeout`.
    pub fn read(self: *Socket, buf: []u8) !usize {
        var data: [1][]u8 = .{buf};
        var storage: [1]Io.Operation.Storage = undefined;
        var batch: Io.Batch = .init(&storage);
        defer batch.cancel(self.io);
        _ = batch.add(.{ .net_read = .{ .socket_handle = self.stream.socket.handle, .data = &data } });
        try batch.awaitConcurrent(self.io, .{ .duration = .{ .raw = self.idle_timeout, .clock = .awake } });
        return (try batch.next().?.result.net_read).data_len;
    }
};

fn streamRead(r: *Io.Reader, w: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
    const socket: *Socket = @alignCast(@fieldParentPtr("reader", r));
    const dest = limit.slice(try w.writableSliceGreedy(1));
    const n = socket.read(dest) catch |err| {
        socket.err = err;
        return error.ReadFailed;
    };
    if (n == 0) return error.EndOfStream;
    w.advance(n);
    return n;
}

test "socket read times out when the peer is silent" {
    const io = std.testing.io;
    const loopback = try net.IpAddress.parse("127.0.0.1", 0);
    var listener = try loopback.listen(io, .{});
    defer listener.deinit(io);
    const client = try listener.socket.address.connect(io, .{ .mode = .stream });
    defer client.close(io);
    const accepted = try listener.accept(io);
    defer accepted.close(io);

    var buf: [16]u8 = undefined;
    var socket: Socket = .init(io, accepted, .fromMilliseconds(50), &buf);
    try std.testing.expectError(error.Timeout, socket.read(&buf));

    var peer = client.writer(io, &.{});
    try peer.interface.writeAll("hi\n");
    try std.testing.expectEqualStrings("hi", try socket.reader.takeDelimiter('\n') orelse "");
}

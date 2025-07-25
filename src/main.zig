const std = @import("std");
const net = std.net;
const posix = std.posix;

pub fn main() !void {
    const address = try std.net.Address.parseIp("127.0.0.1", 5882);
    const tpe: u32 = posix.SOCK.STREAM;
    const protocol = posix.IPPROTO.TCP;
    const listener = try posix.socket(address.any.family, tpe, protocol);
    defer posix.close(listener);

    try posix.setsockopt(listener, posix.SOL.SOCKET, posix.SO.REUSEADDR, &std.mem.toBytes(@as(c_int, 1)));
    try posix.bind(listener, &address.any, address.getOsSockLen());
    try printAddress(listener);
    try posix.listen(listener, 128);
    var buf: [128]u8 = undefined;

    while (true) {
        var client_address: net.Address = undefined;
        var client_address_len: posix.socklen_t = @sizeOf(net.Address);

        const socket = posix.accept(listener, &client_address.any, &client_address_len, 0) catch |err| {
            std.debug.print("error accept: {}\n", .{err});
            continue;
        };

        defer posix.close(socket);
        std.debug.print("{} connected\n", .{client_address});

        const timeout = posix.timeval{.sec = 2, .usec = 500_000};
        try posix.setsockopt(socket, posix.SOL.SOCKET, posix.SO.RCVTIMEO, &std.mem.toBytes(timeout));

        try posix.setsockopt(socket, posix.SOL.SOCKET, posix.SO.SNDTIMEO, &std.mem.toBytes(timeout));

        // read from client
        const read = posix.read(socket, &buf) catch |err| {
            std.debug.print("error reading: {}\n", .{err});
            continue;
        };

        if (read == 0) {
            continue;
        }

        write(socket, buf[0..read]) catch |err| {
            std.debug.print("error writing: {}\n", .{err});
        };

        
    }
}

fn printAddress(socket: posix.socket_t) !void {
    var address: std.net.Address = undefined;
    var len: posix.socklen_t = @sizeOf(net.Address);
    try posix.getsockname(socket, &address.any, &len);
    std.debug.print("{}\n", .{address}); 
}

fn write(socket: posix.socket_t, msg: []const u8) !void {
    var pos: usize = 0;
    while (pos < msg.len) {
        const written = try posix.write(socket, msg[pos..]);
        if (written == 0) {
            return error.Closed;
        }
        pos += written; 
    }
}

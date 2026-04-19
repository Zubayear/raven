pub fn main() !void {
    const std = @import("std");

    const allocator = std.heap.page_allocator;
    const Config = @import("config.zig").Config;
    const Server = @import("server.zig").Server;

    var server = Server.init(allocator, Config{});
    try server.run();
}

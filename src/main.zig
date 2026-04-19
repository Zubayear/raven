const std = @import("std");

pub fn main(process: std.process.Init) !void {

    const Config = @import("config.zig").Config;
    const Server = @import("server.zig").Server;

    const config = try Config.load(process);
    std.debug.print("starting raven {s} on {s}:{d} / imap {d} data={s}\n", .{ config.hostname, config.listen_address, config.listen_port, config.imap_port, config.data_dir });

    var server = Server.init(process.arena.allocator(), config);
    try server.run();
}

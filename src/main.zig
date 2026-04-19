const std = @import("std");

pub fn main(process: std.process.Init) !void {
    const io = process.io;
    const allocator = process.arena.allocator();
    const Config = @import("config.zig").Config;
    const ImapServer = @import("imap.zig").ImapServer;
    const Server = @import("server.zig").Server;
    const TenantCatalog = @import("tenant_index.zig").TenantCatalog;

    const config = try Config.load(process);
    std.debug.print("starting raven {s} on {s}:{d} / imap {d} data={s}\n", .{ config.hostname, config.listen_address, config.listen_port, config.imap_port, config.data_dir });

    var smtp = Server.init(allocator, config);

    try smtp.storage.ensureLayout(io, allocator);

    var tenant_catalog = try TenantCatalog.load(allocator, io, smtp.storage);
    defer tenant_catalog.deinit(allocator);

    var imap = ImapServer.init(allocator, config, smtp.storage, &tenant_catalog);

    var smtp_listener = try smtp.listen(io);
    var imap_listener = try imap.listen(io);

    var shutdown = std.atomic.Value(bool).init(false);
    var signal_set = std.posix.sigfillset();
    std.posix.sigprocmask(std.posix.SIG.BLOCK, &signal_set, null);

    const signal_thread = try std.Thread.spawn(.{}, waitForShutdown, .{ io, &shutdown, &smtp_listener, &imap_listener, &signal_set });
    const smtp_thread = try std.Thread.spawn(.{}, Server.serve, .{ &smtp, io, &smtp_listener, &tenant_catalog, &shutdown });
    const imap_thread = try std.Thread.spawn(.{}, ImapServer.serve, .{ &imap, io, &imap_listener, &shutdown });

    smtp_thread.join();
    imap_thread.join();
    signal_thread.join();
}

fn waitForShutdown(
    io: std.Io,
    shutdown: *std.atomic.Value(bool),
    smtp_listener: *std.Io.net.Server,
    imap_listener: *std.Io.net.Server,
    signal_set: *std.posix.sigset_t,
) void {
    var sig: c_int = 0;
    _ = std.c.sigwait(signal_set, &sig);
    shutdown.store(true, .seq_cst);
    smtp_listener.deinit(io);
    imap_listener.deinit(io);
    std.debug.print("shutdown requested by signal {d}\n", .{sig});
}

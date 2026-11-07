const std = @import("std");

pub fn main(process: std.process.Init) !void {
    const io = process.io;
    const allocator = process.gpa;
    const Config = @import("config.zig").Config;
    const ImapServer = @import("imap.zig").ImapServer;
    const Server = @import("server.zig").Server;
    const TenantCatalog = @import("tenant_index.zig").TenantCatalog;
    const TlsServer = @import("tls.zig").TlsServer;

    const config = try Config.load(process);
    std.debug.print("starting raven {s} on {s}:{d} / imap {d} data={s}\n", .{ config.hostname, config.listen_address, config.listen_port, config.imap_port, config.data_dir });

    var smtp = Server.init(allocator, config);

    try smtp.storage.ensureLayout(io, allocator);

    var tenant_catalog = try TenantCatalog.load(allocator, io, smtp.storage);
    defer tenant_catalog.deinit(allocator);

    var imap = ImapServer.init(allocator, config, smtp.storage, &tenant_catalog);

    var tls_server: ?TlsServer = null;
    defer if (tls_server) |*value| value.deinit();
    if (config.tls_cert_file.len != 0 or config.tls_key_file.len != 0) {
        if (config.tls_cert_file.len == 0 or config.tls_key_file.len == 0) return error.InvalidConfig;
        tls_server = try TlsServer.init(allocator, config.tls_cert_file, config.tls_key_file);
        std.debug.print("tls enabled with {s} and {s}\n", .{ config.tls_cert_file, config.tls_key_file });
    }

    var smtp_listener = try smtp.listen(io);
    defer smtp_listener.deinit(io);
    var imap_listener = try imap.listen(io);
    defer imap_listener.deinit(io);

    // Block only SIGINT/SIGTERM for sigwait; std.Io cancelation interrupts
    // blocked syscalls with SIGIO, so that one must stay deliverable.
    var signal_set = std.posix.sigemptyset();
    std.posix.sigaddset(&signal_set, .INT);
    std.posix.sigaddset(&signal_set, .TERM);
    std.posix.sigprocmask(std.posix.SIG.BLOCK, &signal_set, null);

    var shutdown = std.atomic.Value(bool).init(false);
    const tls_ptr: ?*TlsServer = if (tls_server) |*value| value else null;
    var smtp_task = try io.concurrent(Server.serve, .{ &smtp, io, &smtp_listener, &tenant_catalog, &shutdown, tls_ptr });
    var imap_task = try io.concurrent(ImapServer.serve, .{ &imap, io, &imap_listener, &shutdown, tls_ptr });

    var sig: c_int = 0;
    _ = std.c.sigwait(&signal_set, &sig);
    std.debug.print("shutdown requested by signal {d}\n", .{sig});
    shutdown.store(true, .release);
    smtp_task.cancel(io) catch {};
    imap_task.cancel(io) catch {};
}

test {
    _ = @import("account_index.zig");
    _ = @import("address.zig");
    _ = @import("alias_index.zig");
    _ = @import("config.zig");
    _ = @import("imap.zig");
    _ = @import("server.zig");
    _ = @import("storage.zig");
    _ = @import("tenant_index.zig");
}

const std = @import("std");
const Config = @import("config.zig").Config;
const conn = @import("conn.zig");
const ImapServer = @import("imap.zig").ImapServer;
const Server = @import("server.zig").Server;
const Storage = @import("storage.zig").Storage;
const TenantCatalog = @import("tenant_index.zig").TenantCatalog;
const TlsServer = @import("tls.zig").TlsServer;

pub fn main(process: std.process.Init) !void {
    const io = process.io;
    const allocator = process.gpa;

    const config = try Config.load(process);
    std.debug.print("starting raven {s} on {s}:{d} / imap {d} data={s}\n", .{ config.hostname, config.listen_address, config.listen_port, config.imap_port, config.data_dir });

    const storage = Storage.init(config.data_dir);
    try storage.ensureLayout(io, allocator);

    var tenant_catalog = try TenantCatalog.load(allocator, io, storage);
    defer tenant_catalog.deinit(allocator);

    var smtp = Server.init(allocator, config, &tenant_catalog);
    var imap = ImapServer.init(allocator, config, storage, &tenant_catalog);

    var tls_server: ?TlsServer = null;
    defer if (tls_server) |*value| value.deinit();
    if (config.tls_cert_file.len != 0 or config.tls_key_file.len != 0) {
        if (config.tls_cert_file.len == 0 or config.tls_key_file.len == 0) return error.InvalidConfig;
        tls_server = try TlsServer.init(allocator, config.tls_cert_file, config.tls_key_file);
        std.debug.print("tls enabled with {s} and {s}\n", .{ config.tls_cert_file, config.tls_key_file });
    }
    const tls: ?*TlsServer = if (tls_server) |*value| value else null;

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

    var smtp_task = try io.concurrent(conn.Listener(Server).serve, .{
        io, &smtp_listener, &smtp,
        .{
            .max_connections = config.max_connections,
            .idle_timeout = .fromSeconds(5 * 60), // RFC 5321 §4.5.3.2.7
            .busy_reply = "421 4.7.0 too many connections, try again later\r\n",
            .tls = tls,
        },
    });
    var imap_task = try io.concurrent(conn.Listener(ImapServer).serve, .{
        io, &imap_listener, &imap,
        .{
            .max_connections = config.max_connections,
            .idle_timeout = .fromSeconds(30 * 60), // RFC 3501 §5.4 autologout
            .busy_reply = "* BYE too many connections, try again later\r\n",
            .tls = tls,
        },
    });

    var sig: c_int = 0;
    _ = std.c.sigwait(&signal_set, &sig);
    std.debug.print("shutdown requested by signal {d}\n", .{sig});
    smtp_task.cancel(io);
    imap_task.cancel(io);
}

test {
    _ = @import("account_index.zig");
    _ = @import("address.zig");
    _ = @import("alias_index.zig");
    _ = @import("config.zig");
    _ = @import("conn.zig");
    _ = @import("imap.zig");
    _ = @import("server.zig");
    _ = @import("storage.zig");
    _ = @import("tenant_index.zig");
}

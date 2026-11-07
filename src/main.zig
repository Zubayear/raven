const std = @import("std");
const Io = std.Io;
const account_index = @import("account_index.zig");
const Config = @import("config.zig").Config;
const conn = @import("conn.zig");
const dns = @import("dns.zig");
const ImapServer = @import("imap.zig").ImapServer;
const Server = @import("server.zig").Server;
const Storage = @import("storage.zig").Storage;
const TenantCatalog = @import("tenant_index.zig").TenantCatalog;
const TlsServer = @import("tls.zig").TlsServer;

pub fn main(process: std.process.Init) !void {
    const io = process.io;
    const allocator = process.gpa;

    var args = try std.process.Args.Iterator.initAllocator(process.minimal.args, allocator);
    defer args.deinit();
    _ = args.next();
    if (args.next()) |command| {
        if (std.mem.eql(u8, command, "passwd")) return passwd(io, allocator);
        if (std.mem.eql(u8, command, "mx")) return mx(io, allocator, args.next() orelse return error.MissingDomain);
    }

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

    var smtp_listener = try smtp.listen(io, config.listen_port);
    defer smtp_listener.deinit(io);
    var imap_listener = try imap.listen(io, config.imap_port);
    defer imap_listener.deinit(io);

    // Block only SIGINT/SIGTERM for sigwait; std.Io cancelation interrupts
    // blocked syscalls with SIGIO, so that one must stay deliverable.
    var signal_set = std.posix.sigemptyset();
    std.posix.sigaddset(&signal_set, .INT);
    std.posix.sigaddset(&signal_set, .TERM);
    std.posix.sigprocmask(std.posix.SIG.BLOCK, &signal_set, null);

    const smtp_options: conn.Options = .{
        .max_connections = config.max_connections,
        .idle_timeout = .fromSeconds(5 * 60), // RFC 5321 §4.5.3.2.7
        .busy_reply = "421 4.7.0 too many connections, try again later\r\n",
        .tls = tls, // offered through STARTTLS
    };
    var smtp_task = try io.concurrent(conn.Listener(Server).serve, .{ io, &smtp_listener, &smtp, smtp_options });

    var smtps_listener: ?std.Io.net.Server = if (config.smtps_port != 0) try smtp.listen(io, config.smtps_port) else null;
    defer if (smtps_listener) |*listener| listener.deinit(io);
    var smtps_options = smtp_options;
    smtps_options.implicit_tls = true;
    var smtps_task = if (smtps_listener) |*listener| try io.concurrent(conn.Listener(Server).serve, .{ io, listener, &smtp, smtps_options }) else null;

    var submission = Server.init(allocator, config, &tenant_catalog);
    submission.submission = true;
    var submission_listener: ?std.Io.net.Server = if (config.submission_port != 0) try submission.listen(io, config.submission_port) else null;
    defer if (submission_listener) |*listener| listener.deinit(io);
    var submission_task = if (submission_listener) |*listener| try io.concurrent(conn.Listener(Server).serve, .{ io, listener, &submission, smtp_options }) else null;
    const imap_options: conn.Options = .{
        .max_connections = config.max_connections,
        .idle_timeout = .fromSeconds(30 * 60), // RFC 3501 §5.4 autologout
        .busy_reply = "* BYE too many connections, try again later\r\n",
        .tls = tls, // offered through STARTTLS
    };
    var imap_task = try io.concurrent(conn.Listener(ImapServer).serve, .{ io, &imap_listener, &imap, imap_options });

    var imaps_listener: ?std.Io.net.Server = if (config.imaps_port != 0) try imap.listen(io, config.imaps_port) else null;
    defer if (imaps_listener) |*listener| listener.deinit(io);
    var imaps_options = imap_options;
    imaps_options.implicit_tls = true;
    var imaps_task = if (imaps_listener) |*listener| try io.concurrent(conn.Listener(ImapServer).serve, .{ io, listener, &imap, imaps_options }) else null;

    var sig: c_int = 0;
    _ = std.c.sigwait(&signal_set, &sig);
    std.debug.print("shutdown requested by signal {d}\n", .{sig});
    smtp_task.cancel(io);
    if (smtps_task) |*task| task.cancel(io);
    if (submission_task) |*task| task.cancel(io);
    imap_task.cancel(io);
    if (imaps_task) |*task| task.cancel(io);
}

/// `raven mx <domain>`: prints the mail exchangers Raven would use.
fn mx(io: Io, allocator: std.mem.Allocator, domain: []const u8) !void {
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    var out_buf: [1024]u8 = undefined;
    var stdout = Io.File.stdout().writerStreaming(io, &out_buf);
    for (try dns.lookupMx(arena_state.allocator(), io, domain)) |record| {
        try stdout.interface.print("{d} {s}\n", .{ record.preference, record.host });
    }
    try stdout.interface.flush();
}

/// `raven passwd`: reads a password from stdin and prints its argon2id hash,
/// ready for accounts.txt: `echo "alice $(raven passwd)" >> accounts.txt`.
fn passwd(io: Io, allocator: std.mem.Allocator) !void {
    const stdin = Io.File.stdin();
    // Don't echo the password when a person types it at a terminal.
    const original = if (stdin.isTty(io) catch false) std.posix.tcgetattr(stdin.handle) catch null else null;
    if (original) |termios| {
        var quiet = termios;
        quiet.lflag.ECHO = false;
        try std.posix.tcsetattr(stdin.handle, .FLUSH, quiet);
        std.debug.print("Password: ", .{});
    }
    defer if (original) |termios| {
        std.posix.tcsetattr(stdin.handle, .FLUSH, termios) catch {};
        std.debug.print("\n", .{});
    };

    var buf: [1024]u8 = undefined;
    defer std.crypto.secureZero(u8, &buf);
    var reader = stdin.readerStreaming(io, &buf);
    const password = std.mem.trimEnd(u8, try reader.interface.takeDelimiter('\n') orelse "", "\r");
    if (password.len == 0) {
        std.debug.print("raven passwd: empty password\n", .{});
        return error.EmptyPassword;
    }

    const hash = try account_index.hashPassword(allocator, io, password);
    defer allocator.free(hash);
    var out_buf: [256]u8 = undefined;
    var stdout = Io.File.stdout().writerStreaming(io, &out_buf);
    try stdout.interface.print("{s}\n", .{hash});
    try stdout.interface.flush();
}

test {
    _ = @import("account_index.zig");
    _ = @import("address.zig");
    _ = @import("alias_index.zig");
    _ = @import("config.zig");
    _ = @import("conn.zig");
    _ = @import("dns.zig");
    _ = @import("imap.zig");
    _ = @import("imap_proto.zig");
    _ = @import("mime.zig");
    _ = @import("server.zig");
    _ = @import("storage.zig");
    _ = @import("tenant_index.zig");
}

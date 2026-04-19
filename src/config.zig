const std = @import("std");

pub const Config = struct {
    listen_address: []const u8 = "127.0.0.1",
    listen_port: u16 = 5882,
    imap_port: u16 = 1143,
    hostname: []const u8 = "localhost",
    data_dir: []const u8 = "data",
};

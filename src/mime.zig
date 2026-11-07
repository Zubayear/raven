//! Just enough RFC 5322 / MIME parsing for IMAP FETCH: header fields,
//! the part tree, ENVELOPE and BODYSTRUCTURE (RFC 3501 §7.4.2).
const std = @import("std");
const Io = std.Io;
const writeString = @import("imap_proto.zig").writeString;

pub const Part = struct {
    /// Header block including its terminating blank line.
    header: []const u8,
    body: []const u8,
    media_type: []const u8,
    subtype: []const u8,
    /// Raw `; name=value` parameter text of Content-Type.
    params: []const u8,
    /// Sub-parts of a multipart part.
    children: []Part = &.{},
    /// The embedded message of a message/rfc822 part.
    message: ?*Part = null,

    fn is(self: Part, media_type: []const u8, subtype: []const u8) bool {
        return std.ascii.eqlIgnoreCase(self.media_type, media_type) and std.ascii.eqlIgnoreCase(self.subtype, subtype);
    }
};

/// Deeper nesting is treated as opaque data, so hostile messages can't
/// exhaust the stack.
const max_depth = 16;
/// A 25 MiB message can hold millions of empty parts; refuse instead of
/// allocating a tree for all of them.
const max_parts = 1000;

pub const Error = error{ OutOfMemory, TooManyParts };

/// The whole part tree, for BODYSTRUCTURE and numbered sections.
pub fn parse(arena: std.mem.Allocator, raw: []const u8) Error!Part {
    var budget: usize = max_parts;
    return parseDepth(arena, raw, .{ "text", "plain" }, 0, &budget);
}

/// Only the top-level header and body: enough for ENVELOPE, HEADER, TEXT.
pub fn parseShallow(arena: std.mem.Allocator, raw: []const u8) Error!Part {
    var budget: usize = max_parts;
    return parseDepth(arena, raw, .{ "text", "plain" }, max_depth, &budget);
}

fn parseDepth(arena: std.mem.Allocator, raw: []const u8, default_type: [2][]const u8, depth: usize, budget: *usize) Error!Part {
    const split = splitHeader(raw);
    var part: Part = .{ .header = split[0], .body = split[1], .media_type = default_type[0], .subtype = default_type[1], .params = "" };
    if (try field(arena, part.header, "Content-Type")) |value| {
        const semi = std.mem.indexOfScalar(u8, value, ';') orelse value.len;
        const slash = std.mem.indexOfScalar(u8, value[0..semi], '/');
        if (slash) |s| {
            part.media_type = std.mem.trim(u8, value[0..s], " \t");
            part.subtype = std.mem.trim(u8, value[s + 1 .. semi], " \t");
            part.params = value[semi..];
        }
    }
    if (depth >= max_depth) return part;

    if (std.ascii.eqlIgnoreCase(part.media_type, "multipart")) {
        const boundary = param(part.params, "boundary") orelse return part;
        const child_default: [2][]const u8 = if (std.ascii.eqlIgnoreCase(part.subtype, "digest")) .{ "message", "rfc822" } else .{ "text", "plain" };
        const raw_children = try splitParts(arena, part.body, boundary, budget);
        const children = try arena.alloc(Part, raw_children.len);
        for (children, raw_children) |*child, child_raw| child.* = try parseDepth(arena, child_raw, child_default, depth + 1, budget);
        part.children = children;
    } else if (part.is("message", "rfc822")) {
        const inner = try arena.create(Part);
        inner.* = try parseDepth(arena, part.body, .{ "text", "plain" }, depth + 1, budget);
        part.message = inner;
    }
    return part;
}

/// Splits at the first empty line; the header keeps its blank line.
fn splitHeader(raw: []const u8) [2][]const u8 {
    if (std.mem.startsWith(u8, raw, "\r\n")) return .{ raw[0..2], raw[2..] };
    if (std.mem.indexOf(u8, raw, "\r\n\r\n")) |i| return .{ raw[0 .. i + 4], raw[i + 4 ..] };
    if (std.mem.indexOf(u8, raw, "\n\n")) |i| return .{ raw[0 .. i + 2], raw[i + 2 ..] };
    return .{ raw, "" };
}

/// Splits a multipart body on `--boundary` delimiter lines (RFC 2046
/// §5.1.1). The CRLF before a delimiter belongs to the delimiter.
fn splitParts(arena: std.mem.Allocator, body: []const u8, boundary: []const u8, budget: *usize) Error![]const []const u8 {
    var parts = std.ArrayList([]const u8).empty;
    var part_start: ?usize = null;
    var pos: usize = 0;
    while (pos < body.len) {
        const line_end = std.mem.indexOfScalarPos(u8, body, pos, '\n') orelse body.len;
        const line = std.mem.trimEnd(u8, body[pos..line_end], "\r \t");
        if (std.mem.startsWith(u8, line, "--") and std.mem.startsWith(u8, line[2..], boundary)) {
            const rest = line[2 + boundary.len ..];
            const close = std.mem.eql(u8, rest, "--");
            if (rest.len == 0 or close) {
                if (part_start) |begin| {
                    if (budget.* == 0) return error.TooManyParts;
                    budget.* -= 1;
                    var stop = pos;
                    if (stop > begin and body[stop - 1] == '\n') stop -= 1;
                    if (stop > begin and body[stop - 1] == '\r') stop -= 1;
                    try parts.append(arena, body[begin..stop]);
                }
                if (close) return parts.items;
                part_start = @min(line_end + 1, body.len);
            }
        }
        pos = line_end + 1;
    }
    if (part_start) |begin| {
        if (budget.* == 0) return error.TooManyParts;
        budget.* -= 1;
        try parts.append(arena, body[begin..]); // unterminated: keep what we have
    }
    return parts.items;
}

/// The first `name` field of `header`, unfolded (RFC 5322 §2.2.3).
pub fn field(arena: std.mem.Allocator, header: []const u8, name: []const u8) !?[]const u8 {
    var lines = std.mem.splitScalar(u8, header, '\n');
    while (lines.next()) |line| {
        if (line.len <= name.len or line[name.len] != ':' or !std.ascii.eqlIgnoreCase(line[0..name.len], name)) continue;
        var value = std.ArrayList(u8).empty;
        try value.appendSlice(arena, std.mem.trim(u8, line[name.len + 1 ..], " \t\r"));
        while (lines.peek()) |next| {
            if (next.len == 0 or (next[0] != ' ' and next[0] != '\t')) break;
            _ = lines.next();
            try value.append(arena, ' ');
            try value.appendSlice(arena, std.mem.trim(u8, next, " \t\r"));
        }
        return value.items;
    }
    return null;
}

/// A Content-Type parameter value, unquoted (no RFC 2231 decoding).
pub fn param(params: []const u8, name: []const u8) ?[]const u8 {
    var it = ParamIterator{ .text = params };
    while (it.next()) |p| {
        if (std.ascii.eqlIgnoreCase(p.name, name)) return p.value;
    }
    return null;
}

const ParamIterator = struct {
    text: []const u8,
    pos: usize = 0,

    const Param = struct { name: []const u8, value: []const u8 };

    fn next(it: *ParamIterator) ?Param {
        while (it.pos < it.text.len) {
            const semi = std.mem.indexOfScalarPos(u8, it.text, it.pos, ';') orelse return null;
            const eq = std.mem.indexOfScalarPos(u8, it.text, semi, '=') orelse return null;
            const name = std.mem.trim(u8, it.text[semi + 1 .. eq], " \t");
            var start = eq + 1;
            while (start < it.text.len and (it.text[start] == ' ' or it.text[start] == '\t')) start += 1;
            if (start < it.text.len and it.text[start] == '"') {
                const close = std.mem.indexOfScalarPos(u8, it.text, start + 1, '"') orelse it.text.len;
                it.pos = @min(close + 1, it.text.len);
                if (name.len != 0) return .{ .name = name, .value = it.text[start + 1 .. close] };
            } else {
                const end = std.mem.indexOfScalarPos(u8, it.text, start, ';') orelse it.text.len;
                it.pos = end;
                if (name.len != 0) return .{ .name = name, .value = std.mem.trim(u8, it.text[start..end], " \t") };
            }
        }
        return null;
    }
};

/// Finds the part addressed by an IMAP section path such as `1.2`
/// (RFC 3501 §6.4.5). A non-multipart message is its own part 1.
pub fn findPart(root: *const Part, path: []const u32) ?*const Part {
    var part = root;
    for (path) |n| {
        if (part.message) |inner| part = inner;
        if (part.children.len == 0) {
            if (n != 1) return null;
            continue;
        }
        if (n == 0 or n > part.children.len) return null;
        part = &part.children[n - 1];
    }
    return part;
}

// ENVELOPE ------------------------------------------------------------------

pub fn writeEnvelope(arena: std.mem.Allocator, w: *Io.Writer, header: []const u8) !void {
    try w.writeByte('(');
    try writeNString(w, try field(arena, header, "Date"));
    try w.writeByte(' ');
    try writeNString(w, try field(arena, header, "Subject"));
    const from = try field(arena, header, "From");
    // Sender and Reply-To default to From (RFC 3501 §7.4.2).
    for ([_]?[]const u8{ from, try field(arena, header, "Sender") orelse from, try field(arena, header, "Reply-To") orelse from, try field(arena, header, "To"), try field(arena, header, "Cc"), try field(arena, header, "Bcc") }) |addresses| {
        try w.writeByte(' ');
        try writeAddressList(w, addresses);
    }
    try w.writeByte(' ');
    try writeNString(w, try field(arena, header, "In-Reply-To"));
    try w.writeByte(' ');
    try writeNString(w, try field(arena, header, "Message-ID"));
    try w.writeByte(')');
}

fn writeNString(w: *Io.Writer, value: ?[]const u8) !void {
    if (value) |v| try writeString(w, v) else try w.writeAll("NIL");
}

/// RFC 5322 address list as IMAP `((name adl mailbox host) ...)`; groups
/// become `(NIL NIL "group" NIL) ... (NIL NIL NIL NIL)`.
fn writeAddressList(w: *Io.Writer, value: ?[]const u8) !void {
    const list = value orelse return w.writeAll("NIL");
    var wrote = false;
    var it = AddressIterator{ .text = list };
    while (it.next()) |item| {
        if (!wrote) try w.writeByte('(');
        wrote = true;
        switch (item) {
            .group_start => |name| {
                try w.writeAll("(NIL NIL ");
                try writeString(w, name);
                try w.writeAll(" NIL)");
            },
            .group_end => try w.writeAll("(NIL NIL NIL NIL)"),
            .mailbox => |m| {
                try w.writeByte('(');
                try writeNString(w, if (m.name.len == 0) null else m.name);
                try w.writeAll(" NIL ");
                const at = std.mem.lastIndexOfScalar(u8, m.address, '@');
                try writeString(w, if (at) |i| m.address[0..i] else m.address);
                try w.writeByte(' ');
                try writeNString(w, if (at) |i| m.address[i + 1 ..] else null);
                try w.writeByte(')');
            },
        }
    }
    try w.writeAll(if (wrote) ")" else "NIL");
}

const AddressIterator = struct {
    text: []const u8,
    pos: usize = 0,
    pending_group_end: bool = false,

    const Item = union(enum) {
        mailbox: struct { name: []const u8, address: []const u8 },
        group_start: []const u8,
        group_end,
    };

    fn next(it: *AddressIterator) ?Item {
        if (it.pending_group_end) {
            it.pending_group_end = false;
            return .group_end;
        }
        while (it.pos < it.text.len) {
            // An item runs to a top-level ',' (next address), ':' (it was a
            // group name) or ';' (end of group).
            const start = it.pos;
            var depth: usize = 0;
            var quoted = false;
            var angle = false;
            var end = start;
            var stop: u8 = 0;
            while (end < it.text.len) : (end += 1) {
                const ch = it.text[end];
                if (quoted) {
                    if (ch == '\\') end += 1 else if (ch == '"') quoted = false;
                    continue;
                }
                switch (ch) {
                    '"' => quoted = true,
                    '(' => depth += 1,
                    ')' => depth -|= 1,
                    '<' => angle = true,
                    '>' => angle = false,
                    ',', ';', ':' => if (depth == 0 and !angle) {
                        stop = ch;
                        break;
                    },
                    else => {},
                }
            }
            it.pos = @min(end + 1, it.text.len);
            const raw = std.mem.trim(u8, it.text[start..@min(end, it.text.len)], " \t");
            switch (stop) {
                ':' => return .{ .group_start = unquote(stripComments(raw)) },
                ';' => {
                    if (raw.len == 0) return .group_end;
                    it.pending_group_end = true;
                    return mailbox(raw);
                },
                else => if (raw.len != 0) return mailbox(raw),
            }
        }
        return null;
    }

    fn mailbox(raw: []const u8) Item {
        if (std.mem.lastIndexOfScalar(u8, raw, '<')) |open| {
            const close = std.mem.indexOfScalarPos(u8, raw, open, '>') orelse raw.len;
            return .{ .mailbox = .{ .name = unquote(std.mem.trim(u8, stripComments(raw[0..open]), " \t")), .address = std.mem.trim(u8, raw[open + 1 .. close], " \t") } };
        }
        return .{ .mailbox = .{ .name = "", .address = std.mem.trim(u8, stripComments(raw), " \t") } };
    }
};

fn stripComments(s: []const u8) []const u8 {
    const open = std.mem.indexOfScalar(u8, s, '(') orelse return s;
    return std.mem.trim(u8, s[0..open], " \t");
}

fn unquote(s: []const u8) []const u8 {
    if (s.len >= 2 and s[0] == '"' and s[s.len - 1] == '"') return s[1 .. s.len - 1];
    return s;
}

// BODYSTRUCTURE ---------------------------------------------------------------

/// BODY (`extended` false) or BODYSTRUCTURE (`extended` true).
pub fn writeBodyStructure(arena: std.mem.Allocator, w: *Io.Writer, part: *const Part, extended: bool) !void {
    try w.writeByte('(');
    if (part.children.len != 0) {
        for (part.children) |*child| try writeBodyStructure(arena, w, child, extended);
        try w.writeByte(' ');
        try writeString(w, part.subtype);
        if (extended) {
            try w.writeByte(' ');
            try writeParams(w, part.params);
            try w.writeAll(" NIL NIL NIL");
        }
        return w.writeByte(')');
    }

    try writeString(w, part.media_type);
    try w.writeByte(' ');
    try writeString(w, part.subtype);
    try w.writeByte(' ');
    if (std.ascii.eqlIgnoreCase(part.media_type, "text") and param(part.params, "charset") == null) {
        try w.writeAll("(\"charset\" \"us-ascii\")"); // the RFC 2045 default
    } else try writeParams(w, part.params);
    try w.writeByte(' ');
    try writeNString(w, try field(arena, part.header, "Content-ID"));
    try w.writeByte(' ');
    try writeNString(w, try field(arena, part.header, "Content-Description"));
    try w.writeByte(' ');
    try writeString(w, try field(arena, part.header, "Content-Transfer-Encoding") orelse "7bit");
    try w.print(" {d}", .{part.body.len});

    if (part.message) |inner| {
        try w.writeByte(' ');
        try writeEnvelope(arena, w, inner.header);
        try w.writeByte(' ');
        try writeBodyStructure(arena, w, inner, extended);
        try w.print(" {d}", .{lineCount(part.body)});
    } else if (std.ascii.eqlIgnoreCase(part.media_type, "text")) {
        try w.print(" {d}", .{lineCount(part.body)});
    }

    if (extended) {
        try w.writeAll(" NIL "); // MD5
        if (try field(arena, part.header, "Content-Disposition")) |disposition| {
            const semi = std.mem.indexOfScalar(u8, disposition, ';') orelse disposition.len;
            try w.writeByte('(');
            try writeString(w, std.mem.trim(u8, disposition[0..semi], " \t"));
            try w.writeByte(' ');
            try writeParams(w, disposition[semi..]);
            try w.writeByte(')');
        } else try w.writeAll("NIL");
        try w.writeAll(" NIL NIL"); // language, location
    }
    try w.writeByte(')');
}

fn writeParams(w: *Io.Writer, params: []const u8) !void {
    var it = ParamIterator{ .text = params };
    var wrote = false;
    while (it.next()) |p| {
        try w.writeAll(if (wrote) " " else "(");
        wrote = true;
        try writeString(w, p.name);
        try w.writeByte(' ');
        try writeString(w, p.value);
    }
    try w.writeAll(if (wrote) ")" else "NIL");
}

fn lineCount(body: []const u8) usize {
    var lines = std.mem.count(u8, body, "\n");
    if (body.len > 0 and body[body.len - 1] != '\n') lines += 1;
    return lines;
}

// Tests -----------------------------------------------------------------------

const multipart_sample =
    "From: \"Alice A.\" <alice@example.com>\r\n" ++
    "To: bob@example.net, Team: carol@example.org, dan@example.org;\r\n" ++
    "Subject: report\r\n" ++
    "Message-ID: <1@example.com>\r\n" ++
    "Content-Type: multipart/mixed;\r\n boundary=\"XYZ\"\r\n" ++
    "\r\n" ++
    "preamble\r\n" ++
    "--XYZ\r\n" ++
    "Content-Type: text/plain; charset=utf-8\r\n" ++
    "\r\n" ++
    "hello\r\nworld\r\n" ++
    "--XYZ\r\n" ++
    "Content-Type: application/pdf; name=\"r.pdf\"\r\n" ++
    "Content-Transfer-Encoding: base64\r\n" ++
    "Content-Disposition: attachment; filename=\"r.pdf\"\r\n" ++
    "\r\n" ++
    "JVBERi0=\r\n" ++
    "--XYZ--\r\n" ++
    "epilogue\r\n";

test "parses a multipart message into parts" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const root = try parse(arena, multipart_sample);
    try std.testing.expect(root.is("multipart", "mixed"));
    try std.testing.expectEqualStrings("XYZ", param(root.params, "boundary").?);
    try std.testing.expectEqual(@as(usize, 2), root.children.len);
    try std.testing.expectEqualStrings("hello\r\nworld", root.children[0].body);
    try std.testing.expectEqualStrings("JVBERi0=", findPart(&root, &.{2}).?.body);
    try std.testing.expect(findPart(&root, &.{3}) == null);

    const single = try parse(arena, "Subject: x\r\n\r\nbody\r\n");
    try std.testing.expect(single.is("text", "plain"));
    try std.testing.expectEqualStrings("body\r\n", findPart(&single, &.{1}).?.body);
}

test "unfolds header fields" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const value = try field(arena_state.allocator(), "Subject: a\r\n  long\r\n\tsubject\r\nX: y\r\n\r\n", "subject");
    try std.testing.expectEqualStrings("a long subject", value.?);
}

test "envelope with names, groups and defaults" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    var out: Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    try writeEnvelope(arena_state.allocator(), &out.writer, splitHeader(multipart_sample)[0]);
    try std.testing.expectEqualStrings("(NIL \"report\" " ++
        "((\"Alice A.\" NIL \"alice\" \"example.com\")) ((\"Alice A.\" NIL \"alice\" \"example.com\")) ((\"Alice A.\" NIL \"alice\" \"example.com\")) " ++
        "((NIL NIL \"bob\" \"example.net\")(NIL NIL \"Team\" NIL)(NIL NIL \"carol\" \"example.org\")(NIL NIL \"dan\" \"example.org\")(NIL NIL NIL NIL)) " ++
        "NIL NIL NIL \"<1@example.com>\")", out.written());
}

test "bodystructure for multipart with attachment" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const root = try parse(arena, multipart_sample);

    var out: Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    try writeBodyStructure(arena, &out.writer, &root, true);
    try std.testing.expectEqualStrings("((\"text\" \"plain\" (\"charset\" \"utf-8\") NIL NIL \"7bit\" 12 2 NIL NIL NIL NIL)" ++
        "(\"application\" \"pdf\" (\"name\" \"r.pdf\") NIL NIL \"base64\" 8 NIL (\"attachment\" (\"filename\" \"r.pdf\")) NIL NIL)" ++
        " \"mixed\" (\"boundary\" \"XYZ\") NIL NIL NIL)", out.written());

    out.clearRetainingCapacity();
    try writeBodyStructure(arena, &out.writer, &(try parse(arena, "Subject: x\r\n\r\nbody\r\n")), false);
    try std.testing.expectEqualStrings("(\"text\" \"plain\" (\"charset\" \"us-ascii\") NIL NIL \"7bit\" 6 1)", out.written());
}

test "message/rfc822 parts nest an envelope and structure" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const root = try parse(arena, "Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: message/rfc822\r\n\r\n" ++
        "Subject: inner\r\n\r\nhi\r\n--b--\r\n");
    const attached = findPart(&root, &.{1}).?;
    try std.testing.expect(attached.message != null);
    try std.testing.expectEqualStrings("hi", findPart(&root, &.{ 1, 1 }).?.body);

    var out: Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    try writeBodyStructure(arena, &out.writer, attached, false);
    try std.testing.expectStringStartsWith(out.written(), "(\"message\" \"rfc822\" NIL NIL NIL \"7bit\" 20 (NIL \"inner\" NIL NIL NIL NIL NIL NIL NIL NIL) (\"text\" \"plain\"");
}

test "nesting deeper than the limit stays opaque" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    var raw: Io.Writer.Allocating = .init(std.testing.allocator);
    defer raw.deinit();
    for (0..max_depth + 4) |_| try raw.writer.writeAll("Content-Type: message/rfc822\r\n\r\n");
    _ = try parse(arena_state.allocator(), raw.written());
}

test "part count is bounded" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    var raw: Io.Writer.Allocating = .init(std.testing.allocator);
    defer raw.deinit();
    try raw.writer.writeAll("Content-Type: multipart/mixed; boundary=b\r\n\r\n");
    for (0..max_parts + 1) |_| try raw.writer.writeAll("--b\r\n");
    try std.testing.expectError(error.TooManyParts, parse(arena_state.allocator(), raw.written()));
    // A shallow parse never splits, so it is unaffected.
    _ = try parseShallow(arena_state.allocator(), raw.written());
}

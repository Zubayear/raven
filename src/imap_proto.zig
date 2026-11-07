//! IMAP4rev1 wire format (RFC 3501 §9): reading whole commands, literals
//! included, and parsing their arguments.
const std = @import("std");
const Io = std.Io;

pub const Input = union(enum) {
    /// The full command; literal data sits right after its `{n}` marker.
    command: []u8,
    /// The line did not fit in the read buffer and was skipped.
    too_long,
    /// A synchronizing literal over the limit was announced; the client is
    /// waiting for our refusal. Holds the command's tag.
    literal_refused: []const u8,
};

/// Reads one command. Synchronizing literals (`{n}`) get a `+` continuation;
/// LITERAL+ ones (`{n+}`, RFC 7888) are read straight away. Returns null at
/// end of stream. A non-synchronizing literal over `max_literal` is
/// `error.LiteralTooLarge`: its bytes are already on the way, so hang up.
pub fn readCommand(arena: std.mem.Allocator, r: *Io.Reader, w: *Io.Writer, max_literal: usize) !?Input {
    var command = std.ArrayList(u8).empty;
    while (true) {
        const raw = r.takeDelimiter('\n') catch |err| switch (err) {
            error.StreamTooLong => {
                _ = r.discardDelimiterInclusive('\n') catch |e| switch (e) {
                    error.EndOfStream => return null,
                    else => return e,
                };
                return .too_long;
            },
            else => return err,
        } orelse return if (command.items.len == 0) null else error.EndOfStream;
        const line = if (raw.len > 0 and raw[raw.len - 1] == '\r') raw[0 .. raw.len - 1] else raw;
        try command.appendSlice(arena, line);

        const literal = literalMarker(line) orelse return .{ .command = command.items };
        if (literal.len > max_literal) {
            if (!literal.synchronizing) return error.LiteralTooLarge;
            const tag_end = std.mem.indexOfScalar(u8, command.items, ' ') orelse command.items.len;
            return .{ .literal_refused = command.items[0..tag_end] };
        }
        if (literal.synchronizing) {
            try w.writeAll("+ ready for literal data\r\n");
            try w.flush();
        }
        try r.readSliceAll(try command.addManyAsSlice(arena, literal.len));
    }
}

const Literal = struct { len: usize, synchronizing: bool };

/// `{12}` or `{12+}` ending a line announces a literal.
fn literalMarker(line: []const u8) ?Literal {
    if (line.len < 3 or line[line.len - 1] != '}') return null;
    const open = std.mem.lastIndexOfScalar(u8, line, '{') orelse return null;
    var digits = line[open + 1 .. line.len - 1];
    const plus = std.mem.endsWith(u8, digits, "+");
    if (plus) digits = digits[0 .. digits.len - 1];
    if (digits.len == 0) return null;
    for (digits) |ch| if (!std.ascii.isDigit(ch)) return null;
    return .{ .len = std.fmt.parseInt(usize, digits, 10) catch return null, .synchronizing = !plus };
}

/// Cursor over one command. Unescaped quoted strings are allocated in `arena`.
pub const Parser = struct {
    text: []const u8,
    pos: usize = 0,
    arena: std.mem.Allocator,

    pub const Error = error{ Syntax, OutOfMemory };

    pub fn atEnd(p: *const Parser) bool {
        return p.pos >= p.text.len;
    }

    pub fn end(p: *const Parser) Error!void {
        if (!p.atEnd()) return error.Syntax;
    }

    pub fn peek(p: *const Parser) ?u8 {
        return if (p.atEnd()) null else p.text[p.pos];
    }

    /// Consumes `ch` if it is next.
    pub fn take(p: *Parser, ch: u8) bool {
        if (p.peek() != ch) return false;
        p.pos += 1;
        return true;
    }

    pub fn expect(p: *Parser, ch: u8) Error!void {
        if (!p.take(ch)) return error.Syntax;
    }

    pub fn space(p: *Parser) Error!void {
        return p.expect(' ');
    }

    /// 1*ATOM-CHAR; `extra` lists characters also allowed here (e.g. `]` in
    /// an astring, `%*` in a LIST pattern).
    pub fn atomWith(p: *Parser, extra: []const u8) Error![]const u8 {
        const start = p.pos;
        while (p.peek()) |ch| {
            if (!isAtomChar(ch) and std.mem.indexOfScalar(u8, extra, ch) == null) break;
            p.pos += 1;
        }
        if (p.pos == start) return error.Syntax;
        return p.text[start..p.pos];
    }

    pub fn atom(p: *Parser) Error![]const u8 {
        return p.atomWith("");
    }

    /// atom / quoted / literal.
    pub fn astring(p: *Parser) Error![]const u8 {
        return switch (p.peek() orelse return error.Syntax) {
            '"', '{' => p.string(),
            else => p.atomWith("]"),
        };
    }

    /// quoted / literal.
    pub fn string(p: *Parser) Error![]const u8 {
        if (p.take('"')) return p.quotedRest();
        try p.expect('{');
        const digits_start = p.pos;
        while (p.peek()) |ch| : (p.pos += 1) if (!std.ascii.isDigit(ch)) break;
        const len = std.fmt.parseInt(usize, p.text[digits_start..p.pos], 10) catch return error.Syntax;
        _ = p.take('+');
        try p.expect('}');
        if (p.text.len - p.pos < len) return error.Syntax;
        defer p.pos += len;
        return p.text[p.pos..][0..len];
    }

    fn quotedRest(p: *Parser) Error![]const u8 {
        const start = p.pos;
        var escaped = false;
        while (p.peek()) |ch| : (p.pos += 1) {
            switch (ch) {
                '"' => break,
                '\\' => {
                    escaped = true;
                    p.pos += 1;
                    const next = p.peek() orelse return error.Syntax;
                    if (next != '"' and next != '\\') return error.Syntax;
                },
                '\r', '\n', 0 => return error.Syntax,
                else => {},
            }
        } else return error.Syntax;
        const raw = p.text[start..p.pos];
        p.pos += 1; // closing quote
        if (!escaped) return raw;

        var out = try p.arena.alloc(u8, raw.len);
        var n: usize = 0;
        var i: usize = 0;
        while (i < raw.len) : (i += 1) {
            if (raw[i] == '\\') i += 1;
            out[n] = raw[i];
            n += 1;
        }
        return out[0..n];
    }

    pub fn number(p: *Parser) Error!u32 {
        const start = p.pos;
        while (p.peek()) |ch| : (p.pos += 1) if (!std.ascii.isDigit(ch)) break;
        return std.fmt.parseInt(u32, p.text[start..p.pos], 10) catch error.Syntax;
    }

    pub fn sequenceSet(p: *Parser) Error!SequenceSet {
        const start = p.pos;
        while (p.peek()) |ch| : (p.pos += 1) {
            if (!std.ascii.isDigit(ch) and ch != ':' and ch != ',' and ch != '*') break;
        }
        const set: SequenceSet = .{ .text = p.text[start..p.pos] };
        try set.validate();
        return set;
    }
};

/// ATOM-CHAR: any CHAR except atom-specials (RFC 3501 §9).
fn isAtomChar(ch: u8) bool {
    return ch > 0x20 and ch < 0x7f and std.mem.indexOfScalar(u8, "(){%*\"\\]", ch) == null;
}

/// `1:3,7,9:*` (RFC 3501 §9 sequence-set), over sequence numbers or UIDs.
pub const SequenceSet = struct {
    text: []const u8,

    fn validate(self: SequenceSet) error{Syntax}!void {
        if (self.text.len == 0) return error.Syntax;
        var parts = std.mem.splitScalar(u8, self.text, ',');
        while (parts.next()) |part| {
            var bounds = std.mem.splitScalar(u8, part, ':');
            var count: usize = 0;
            while (bounds.next()) |text| : (count += 1) {
                if (std.mem.eql(u8, text, "*")) continue;
                const n = std.fmt.parseInt(u32, text, 10) catch return error.Syntax;
                if (n == 0) return error.Syntax;
            }
            if (count == 0 or count > 2) return error.Syntax;
        }
    }

    /// Whether `n` is in the set, with `*` standing for `largest`.
    pub fn contains(self: SequenceSet, n: u32, largest: u32) bool {
        var parts = std.mem.splitScalar(u8, self.text, ',');
        while (parts.next()) |part| {
            const colon = std.mem.indexOfScalar(u8, part, ':');
            const a = bound(part[0 .. colon orelse part.len], largest);
            const b = if (colon) |c| bound(part[c + 1 ..], largest) else a;
            if (n >= @min(a, b) and n <= @max(a, b)) return true;
        }
        return false;
    }

    fn bound(text: []const u8, largest: u32) u32 {
        if (std.mem.eql(u8, text, "*")) return largest;
        return std.fmt.parseInt(u32, text, 10) catch unreachable; // validated
    }
};

/// Writes `s` as an IMAP string: quoted when safe, otherwise a literal.
pub fn writeString(w: *Io.Writer, s: []const u8) !void {
    for (s) |ch| {
        if (ch < 0x20 or ch > 0x7e) return w.print("{{{d}}}\r\n{s}", .{ s.len, s });
    }
    try w.writeByte('"');
    for (s) |ch| {
        if (ch == '"' or ch == '\\') try w.writeByte('\\');
        try w.writeByte(ch);
    }
    try w.writeByte('"');
}

fn testRead(input: []const u8, max_literal: usize) !struct { ?Input, []const u8, std.heap.ArenaAllocator } {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    errdefer arena.deinit();
    var r: Io.Reader = .fixed(input);
    var out: Io.Writer.Allocating = .init(arena.allocator());
    const result = try readCommand(arena.allocator(), &r, &out.writer, max_literal);
    return .{ result, out.written(), arena };
}

test "readCommand inlines synchronizing and LITERAL+ literals" {
    const result, const continuation, var arena = try testRead("a1 LOGIN {5}\r\nalice {6+}\r\nse cre\r\na2 NOOP\r\n", 100);
    defer arena.deinit();
    try std.testing.expectEqualStrings("a1 LOGIN {5}alice {6+}se cre", result.?.command);
    try std.testing.expectEqualStrings("+ ready for literal data\r\n", continuation);

    var p: Parser = .{ .text = result.?.command, .arena = arena.allocator() };
    try std.testing.expectEqualStrings("a1", try p.atomWith("]"));
    try p.space();
    try std.testing.expectEqualStrings("LOGIN", try p.atom());
    try p.space();
    try std.testing.expectEqualStrings("alice", try p.astring());
    try p.space();
    try std.testing.expectEqualStrings("se cre", try p.astring());
    try p.end();
}

test "readCommand refuses oversized literals" {
    {
        const result, const continuation, var arena = try testRead("a1 APPEND INBOX {999}\r\n", 10);
        defer arena.deinit();
        try std.testing.expectEqualStrings("a1", result.?.literal_refused);
        try std.testing.expectEqualStrings("", continuation);
    }
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var r: Io.Reader = .fixed("a1 APPEND INBOX {999+}\r\n");
    var out: Io.Writer.Allocating = .init(arena.allocator());
    try std.testing.expectError(error.LiteralTooLarge, readCommand(arena.allocator(), &r, &out.writer, 10));
}

test "parser reads quoted strings with escapes" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var p: Parser = .{ .text = "\"pass word\" \"a\\\"b\\\\c\" \"\"", .arena = arena.allocator() };
    try std.testing.expectEqualStrings("pass word", try p.astring());
    try p.space();
    try std.testing.expectEqualStrings("a\"b\\c", try p.astring());
    try p.space();
    try std.testing.expectEqualStrings("", try p.astring());
    try p.end();

    for ([_][]const u8{ "\"unterminated", "\"bad \\x escape\"", "(", "" }) |bad| {
        var q: Parser = .{ .text = bad, .arena = arena.allocator() };
        try std.testing.expectError(error.Syntax, q.astring());
    }
}

test "sequence sets" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var p: Parser = .{ .text = "2,4:7,9:*", .arena = arena.allocator() };
    const set = try p.sequenceSet();
    try p.end();
    for ([_]u32{ 2, 4, 5, 7, 9, 12 }) |n| try std.testing.expect(set.contains(n, 12));
    for ([_]u32{ 1, 3, 8, 13 }) |n| try std.testing.expect(!set.contains(n, 12));

    const reversed: SequenceSet = .{ .text = "*:3" };
    try std.testing.expect(reversed.contains(5, 5) and reversed.contains(3, 5) and !reversed.contains(2, 5));

    for ([_][]const u8{ "0", "1::2", "1:2:3", ",", "1,", "a" }) |bad| {
        var q: Parser = .{ .text = bad, .arena = arena.allocator() };
        if (q.sequenceSet()) |_| {
            std.debug.print("accepted bad set {s}\n", .{bad});
            return error.TestUnexpectedResult;
        } else |_| {}
    }
}

test "writeString quotes or falls back to a literal" {
    var out: Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    try writeString(&out.writer, "INBOX");
    try writeString(&out.writer, "say \"hi\"");
    try writeString(&out.writer, "caf\xc3\xa9");
    try std.testing.expectEqualStrings("\"INBOX\"\"say \\\"hi\\\"\"{5}\r\ncaf\xc3\xa9", out.written());
}

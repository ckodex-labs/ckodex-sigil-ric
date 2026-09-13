const std = @import("std");
const unicode_props = @import("unicode_props.zig");

pub const EncodingFamily = enum {
    gpt2_like,
    cl100k_like,
    o200k_like,
};

pub const TokenSpan = extern struct {
    token_id: u32,
    start: usize,
    end: usize,
};

pub const TokenBuffer = extern struct {
    items: ?[*]TokenSpan,
    len: usize,
};

pub const ByteBuffer = extern struct {
    items: ?[*]u8,
    len: usize,
};

const Range = struct {
    start: usize,
    end: usize,
};

const TokenSegment = struct {
    start: usize,
    end: usize,
};

const ErrorCode = enum(c_int) {
    ok = 0,
    unknown_encoding = 1,
    invalid_utf8 = 2,
    token_not_found = 3,
    alloc_failed = 4,
    invalid_input = 5,
};

fn code(err: ErrorCode) c_int {
    return @intFromEnum(err);
}

fn isLetter(cp: u21) bool {
    return unicode_props.isLetter(cp);
}

fn isNumber(cp: u21) bool {
    return unicode_props.isNumber(cp);
}

fn isMark(cp: u21) bool {
    return unicode_props.isMark(cp);
}

fn isWhitespace(cp: u21) bool {
    return unicode_props.isWhitespace(cp);
}

fn isUpper(cp: u21) bool {
    return unicode_props.isUpper(cp);
}

fn isLower(cp: u21) bool {
    return unicode_props.isLower(cp);
}

fn isTitle(cp: u21) bool {
    return unicode_props.isTitle(cp);
}

fn isModifierLetter(cp: u21) bool {
    return unicode_props.isModifierLetter(cp);
}

fn isOtherLetter(cp: u21) bool {
    return unicode_props.isOtherLetter(cp);
}

fn isAlphaLike(cp: u21) bool {
    return isLetter(cp) or isMark(cp);
}

fn decodeCodepoint(text: []const u8, idx: usize) !struct { cp: u21, len: usize } {
    const first = text[idx];
    const len = try std.unicode.utf8ByteSequenceLength(first);
    if (idx + len > text.len) return error.InvalidUtf8;
    const cp = try std.unicode.utf8Decode(text[idx .. idx + len]);
    return .{ .cp = cp, .len = len };
}

fn familyForEncoding(name: []const u8) ?struct { family: EncodingFamily, asset: []const u8 } {
    if (std.mem.eql(u8, name, "gpt2")) return .{ .family = .gpt2_like, .asset = @embedFile("assets/r50k_base.tiktoken") };
    if (std.mem.eql(u8, name, "r50k_base")) return .{ .family = .gpt2_like, .asset = @embedFile("assets/r50k_base.tiktoken") };
    if (std.mem.eql(u8, name, "p50k_base")) return .{ .family = .gpt2_like, .asset = @embedFile("assets/p50k_base.tiktoken") };
    if (std.mem.eql(u8, name, "p50k_edit")) return .{ .family = .gpt2_like, .asset = @embedFile("assets/p50k_base.tiktoken") };
    if (std.mem.eql(u8, name, "cl100k_base")) return .{ .family = .cl100k_like, .asset = @embedFile("assets/cl100k_base.tiktoken") };
    if (std.mem.eql(u8, name, "o200k_base")) return .{ .family = .o200k_like, .asset = @embedFile("assets/o200k_base.tiktoken") };
    if (std.mem.eql(u8, name, "o200k_harmony")) return .{ .family = .o200k_like, .asset = @embedFile("assets/o200k_base.tiktoken") };
    return null;
}

fn specialTokensForEncoding(allocator: std.mem.Allocator, name: []const u8) ![]const SpecialToken {
    var list = std.array_list.Managed(SpecialToken).init(allocator);
    errdefer list.deinit();

    const add = struct {
        fn add(target: *std.array_list.Managed(SpecialToken), gpa: std.mem.Allocator, token: []const u8, id: u32) !void {
            _ = gpa;
            try target.append(.{ .name = token, .id = id });
        }
    }.add;

    if (std.mem.eql(u8, name, "gpt2") or std.mem.eql(u8, name, "r50k_base") or std.mem.eql(u8, name, "p50k_base")) {
        try add(&list, allocator, "<|endoftext|>", 50256);
    } else if (std.mem.eql(u8, name, "p50k_edit")) {
        try add(&list, allocator, "<|endoftext|>", 50256);
        try add(&list, allocator, "<|fim_prefix|>", 50281);
        try add(&list, allocator, "<|fim_middle|>", 50282);
        try add(&list, allocator, "<|fim_suffix|>", 50283);
    } else if (std.mem.eql(u8, name, "cl100k_base")) {
        try add(&list, allocator, "<|endoftext|>", 100257);
        try add(&list, allocator, "<|fim_prefix|>", 100258);
        try add(&list, allocator, "<|fim_middle|>", 100259);
        try add(&list, allocator, "<|fim_suffix|>", 100260);
        try add(&list, allocator, "<|endofprompt|>", 100276);
    } else if (std.mem.eql(u8, name, "o200k_base")) {
        try add(&list, allocator, "<|endoftext|>", 199999);
        try add(&list, allocator, "<|endofprompt|>", 200018);
    } else if (std.mem.eql(u8, name, "o200k_harmony")) {
        try add(&list, allocator, "<|startoftext|>", 199998);
        try add(&list, allocator, "<|endoftext|>", 199999);
        try add(&list, allocator, "<|reserved_200000|>", 200000);
        try add(&list, allocator, "<|reserved_200001|>", 200001);
        try add(&list, allocator, "<|return|>", 200002);
        try add(&list, allocator, "<|constrain|>", 200003);
        try add(&list, allocator, "<|reserved_200004|>", 200004);
        try add(&list, allocator, "<|channel|>", 200005);
        try add(&list, allocator, "<|start|>", 200006);
        try add(&list, allocator, "<|end|>", 200007);
        try add(&list, allocator, "<|message|>", 200008);
        try add(&list, allocator, "<|reserved_200009|>", 200009);
        try add(&list, allocator, "<|reserved_200010|>", 200010);
        try add(&list, allocator, "<|reserved_200011|>", 200011);
        try add(&list, allocator, "<|call|>", 200012);
        var id: u32 = 200013;
        while (id < 201088) : (id += 1) {
            var buf: [32]u8 = undefined;
            const token = try std.fmt.bufPrint(&buf, "<|reserved_{d}|>", .{id});
            try add(&list, allocator, try allocator.dupe(u8, token), id);
        }
    } else {
        return error.UnknownEncoding;
    }

    return list.toOwnedSlice();
}

const SpecialToken = struct {
    name: []const u8,
    id: u32,
};

pub const Tokenizer = struct {
    allocator: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    family: EncodingFamily,
    mergeable_ranks: std.StringHashMapUnmanaged(u32),
    reverse_mergeable: std.AutoHashMapUnmanaged(u32, []const u8),
    special_tokens: std.StringHashMapUnmanaged(u32),
    reverse_special: std.AutoHashMapUnmanaged(u32, []const u8),

    pub fn init(allocator: std.mem.Allocator, name: []const u8) !Tokenizer {
        const spec = familyForEncoding(name) orelse return error.UnknownEncoding;
        var arena = std.heap.ArenaAllocator.init(allocator);
        errdefer arena.deinit();

        var tokenizer = Tokenizer{
            .allocator = allocator,
            .arena = arena,
            .family = spec.family,
            .mergeable_ranks = .{},
            .reverse_mergeable = .{},
            .special_tokens = .{},
            .reverse_special = .{},
        };

        try tokenizer.loadRanks(spec.asset);
        try tokenizer.loadSpecialTokens(name);
        return tokenizer;
    }

    pub fn deinit(self: *Tokenizer) void {
        self.mergeable_ranks.deinit(self.arena.allocator());
        self.reverse_mergeable.deinit(self.arena.allocator());
        self.special_tokens.deinit(self.arena.allocator());
        self.reverse_special.deinit(self.arena.allocator());
        self.arena.deinit();
    }

    fn alloc(self: *Tokenizer) std.mem.Allocator {
        return self.arena.allocator();
    }

    fn loadRanks(self: *Tokenizer, file: []const u8) !void {
        var it = std.mem.splitScalar(u8, file, '\n');
        while (it.next()) |raw_line| {
            const line = std.mem.trim(u8, raw_line, " \t\r");
            if (line.len == 0) continue;
            var parts = std.mem.splitScalar(u8, line, ' ');
            const b64 = parts.next() orelse return error.InvalidInput;
            const rank_str = parts.next() orelse return error.InvalidInput;
            if (parts.next() != null) return error.InvalidInput;

            const decoded_len = try std.base64.standard.Decoder.calcSizeForSlice(b64);
            const bytes = try self.alloc().alloc(u8, decoded_len);
            _ = try std.base64.standard.Decoder.decode(bytes, b64);
            const token = try self.alloc().dupe(u8, bytes);
            const rank = try std.fmt.parseInt(u32, rank_str, 10);

            try self.mergeable_ranks.put(self.alloc(), token, rank);
            try self.reverse_mergeable.put(self.alloc(), rank, token);
        }
    }

    fn loadSpecialTokens(self: *Tokenizer, name: []const u8) !void {
        const specials = try specialTokensForEncoding(self.alloc(), name);
        for (specials) |item| {
            try self.special_tokens.put(self.alloc(), item.name, item.id);
            try self.reverse_special.put(self.alloc(), item.id, item.name);
        }
    }

    fn tokenIdForBytes(self: *Tokenizer, bytes: []const u8) !u32 {
        if (self.special_tokens.get(bytes)) |id| return id;
        if (self.mergeable_ranks.get(bytes)) |id| return id;
        return error.TokenNotFound;
    }

    fn rankForBytes(self: *Tokenizer, bytes: []const u8) ?u32 {
        return self.mergeable_ranks.get(bytes);
    }

    fn bytesForId(self: *Tokenizer, id: u32) ?[]const u8 {
        if (self.reverse_special.get(id)) |bytes| return bytes;
        if (self.reverse_mergeable.get(id)) |bytes| return bytes;
        return null;
    }

    pub fn isSpecialToken(self: *Tokenizer, bytes: []const u8) bool {
        return self.special_tokens.contains(bytes);
    }

    pub fn specialTokenId(self: *Tokenizer, bytes: []const u8) ?u32 {
        return self.special_tokens.get(bytes);
    }

    fn appendPiece(
        self: *Tokenizer,
        out: *std.array_list.Managed(TokenSpan),
        temp_allocator: std.mem.Allocator,
        text: []const u8,
        base_offset: usize,
        start: usize,
        end: usize,
    ) !void {
        const piece = text[start..end];
        if (piece.len == 0) return;

        var segments = std.array_list.Managed(TokenSegment).init(temp_allocator);
        defer segments.deinit();
        try segments.ensureTotalCapacity(piece.len);
        for (0..piece.len) |idx| {
            segments.appendAssumeCapacity(.{ .start = idx, .end = idx + 1 });
        }

        while (segments.items.len > 1) {
            var best_index: ?usize = null;
            var best_rank: u32 = std.math.maxInt(u32);

            var i: usize = 0;
            while (i + 1 < segments.items.len) : (i += 1) {
                const merged = piece[segments.items[i].start..segments.items[i + 1].end];
                if (self.rankForBytes(merged)) |rank| {
                    if (rank < best_rank) {
                        best_rank = rank;
                        best_index = i;
                    }
                }
            }

            const merge_index = best_index orelse break;
            segments.items[merge_index].end = segments.items[merge_index + 1].end;
            _ = segments.orderedRemove(merge_index + 1);
        }

        for (segments.items) |segment| {
            const token_bytes = piece[segment.start..segment.end];
            const token_id = try self.tokenIdForBytes(token_bytes);
            try out.append(.{
                .token_id = token_id,
                .start = base_offset + start + segment.start,
                .end = base_offset + start + segment.end,
            });
        }
    }

    fn consumeWhitespace(text: []const u8, start: usize) !usize {
        var idx = start;
        while (idx < text.len) {
            const decoded = try decodeCodepoint(text, idx);
            if (!isWhitespace(decoded.cp)) break;
            idx += decoded.len;
        }
        return idx;
    }

    fn consumeWhitespaceWithoutSpace(text: []const u8, start: usize) !usize {
        const decoded = try decodeCodepoint(text, start);
        return start + decoded.len;
    }

    fn consumeAsciiContract(text: []const u8, start: usize) ?usize {
        if (start >= text.len or text[start] != '\'') return null;
        const rest = text[start + 1 ..];
        const matches = [_][]const u8{ "s", "t", "m", "d", "ll", "ve", "re" };
        inline for (matches) |suffix| {
            if (rest.len >= suffix.len and std.ascii.eqlIgnoreCase(rest[0..suffix.len], suffix)) {
                return start + 1 + suffix.len;
            }
        }
        return null;
    }

    fn consumeClassRun(text: []const u8, start: usize, comptime class_fn: fn (u21) bool) !usize {
        var idx = start;
        while (idx < text.len) {
            const decoded = try decodeCodepoint(text, idx);
            if (!class_fn(decoded.cp)) break;
            idx += decoded.len;
        }
        return idx;
    }

    fn consumeOtherRun(text: []const u8, start: usize) !usize {
        var idx = start;
        while (idx < text.len) {
            const decoded = try decodeCodepoint(text, idx);
            if (isWhitespace(decoded.cp) or isLetter(decoded.cp) or isNumber(decoded.cp)) break;
            idx += decoded.len;
        }
        return idx;
    }

    fn consumeDigitsLimited(text: []const u8, start: usize, limit: usize) !usize {
        var idx = start;
        var count: usize = 0;
        while (idx < text.len and count < limit) : (count += 1) {
            const decoded = try decodeCodepoint(text, idx);
            if (!isNumber(decoded.cp)) break;
            idx += decoded.len;
        }
        return idx;
    }

    fn appendPiecesForFamily(
        self: *Tokenizer,
        out: *std.array_list.Managed(TokenSpan),
        temp_allocator: std.mem.Allocator,
        text: []const u8,
        base_offset: usize,
    ) !void {
        var idx: usize = 0;
        while (idx < text.len) {
            if (self.family == .gpt2_like) {
                if (consumeAsciiContract(text, idx)) |end| {
                    try self.appendPiece(out, temp_allocator, text, base_offset, idx, end);
                    idx = end;
                    continue;
                }
            }

            switch (self.family) {
                .gpt2_like => {
                    const next = try self.gpt2Chunk(text, idx);
                    try self.appendPiece(out, temp_allocator, text, base_offset, idx, next);
                    idx = next;
                },
                .cl100k_like => {
                    const next = try self.cl100kChunk(text, idx);
                    try self.appendPiece(out, temp_allocator, text, base_offset, idx, next);
                    idx = next;
                },
                .o200k_like => {
                    const next = try self.o200kChunk(text, idx);
                    try self.appendPiece(out, temp_allocator, text, base_offset, idx, next);
                    idx = next;
                },
            }
        }
    }

    fn whitespaceBranch(self: *Tokenizer, text: []const u8, start: usize) !usize {
        _ = self;
        return consumeWhitespace(text, start);
    }

    fn gpt2Chunk(self: *Tokenizer, text: []const u8, start: usize) !usize {
        _ = self;
        const decoded = try decodeCodepoint(text, start);
        const cp = decoded.cp;
        const first = decoded.len;

        if (isWhitespace(cp)) {
            if (cp == ' ' and start + first < text.len) {
                const next = try decodeCodepoint(text, start + first);
                if (isLetter(next.cp)) return consumeClassRun(text, start + first, isAlphaLike);
                if (isNumber(next.cp)) return consumeClassRun(text, start + first, isNumber);
                if (!isWhitespace(next.cp) and !isLetter(next.cp) and !isNumber(next.cp)) return consumeOtherRun(text, start + first);
            }
            if (cp == ' ') {
                return start + first;
            }
            return consumeWhitespaceWithoutSpace(text, start);
        }

        if (isLetter(cp)) return consumeClassRun(text, start, isAlphaLike);
        if (isNumber(cp)) return consumeClassRun(text, start, isNumber);
        return consumeOtherRun(text, start);
    }

    fn cl100kChunk(self: *Tokenizer, text: []const u8, start: usize) !usize {
        const decoded = try decodeCodepoint(text, start);
        const cp = decoded.cp;
        const first = decoded.len;

        if (isWhitespace(cp)) {
            if (cp == ' ' and start + first < text.len) {
                const next = try decodeCodepoint(text, start + first);
                if (isLetter(next.cp)) {
                    const run_end = try consumeClassRun(text, start + first, isAlphaLike);
                    return consumeContractionSuffix(text, run_end) orelse run_end;
                }
                if (!isWhitespace(next.cp) and !isLetter(next.cp) and !isNumber(next.cp)) {
                    const chunk_end = try consumeOtherRun(text, start + first);
                    return self.consumeTrailingNewlines(text, chunk_end);
                }
            }
            return consumeWhitespace(text, start);
        }

        if (!isWhitespace(cp) and !isLetter(cp) and !isNumber(cp)) {
            const chunk_end = try consumeOtherRun(text, start);
            return self.consumeTrailingNewlines(text, chunk_end);
        }

        if (isNumber(cp)) return consumeDigitsLimited(text, start, 3);
        if (isLetter(cp)) {
            const run_end = try consumeClassRun(text, start, isAlphaLike);
            return consumeContractionSuffix(text, run_end) orelse run_end;
        }
        return consumeWhitespace(text, start);
    }

    fn o200kChunk(self: *Tokenizer, text: []const u8, start: usize) !usize {
        const decoded = try decodeCodepoint(text, start);
        const cp = decoded.cp;
        const first = decoded.len;

        if (isWhitespace(cp)) {
            if (cp == ' ' and start + first < text.len) {
                const next = try decodeCodepoint(text, start + first);
                if (isLetter(next.cp)) {
                    const run_end = try self.consumeO200kLetterRun(text, start + first);
                    return consumeContractionSuffix(text, run_end) orelse run_end;
                }
                if (!isWhitespace(next.cp) and !isNumber(next.cp)) {
                    const chunk_end = try consumeOtherRun(text, start + first);
                    return self.consumeTrailingNewlines(text, chunk_end);
                }
            }
            return consumeWhitespace(text, start);
        }

        if (isNumber(cp)) return consumeDigitsLimited(text, start, 3);
        if (isLetter(cp)) {
            const run_end = try self.consumeO200kLetterRun(text, start);
            return consumeContractionSuffix(text, run_end) orelse run_end;
        }
        if (!isWhitespace(cp)) {
            const chunk_end = try consumeOtherRun(text, start);
            return self.consumeTrailingNewlines(text, chunk_end);
        }
        return consumeWhitespace(text, start);
    }

    fn consumeO200kLetterRun(self: *Tokenizer, text: []const u8, start: usize) !usize {
        _ = self;
        var idx = start;
        while (idx < text.len) {
            const decoded = try decodeCodepoint(text, idx);
            if (!(isLetter(decoded.cp) or isMark(decoded.cp))) break;
            idx += decoded.len;
        }
        return idx;
    }

    fn consumeTrailingNewlines(self: *Tokenizer, text: []const u8, start: usize) !usize {
        _ = self;
        var idx = start;
        while (idx < text.len) {
            const decoded = try decodeCodepoint(text, idx);
            if (decoded.cp != '\n' and decoded.cp != '\r') break;
            idx += decoded.len;
        }
        return idx;
    }

    fn consumeContractionSuffix(text: []const u8, start: usize) ?usize {
        if (start >= text.len or text[start] != '\'') return null;
        const rest = text[start + 1 ..];
        const matches = [_][]const u8{ "s", "t", "m", "d", "ll", "ve", "re" };
        inline for (matches) |suffix| {
            if (rest.len >= suffix.len and std.ascii.eqlIgnoreCase(rest[0..suffix.len], suffix)) {
                return start + 1 + suffix.len;
            }
        }
        return null;
    }

    pub fn encodeOrdinaryAlloc(self: *Tokenizer, allocator: std.mem.Allocator, text: []const u8) ![]TokenSpan {
        _ = std.unicode.Utf8View.init(text) catch return error.InvalidUtf8;
        var spans = std.array_list.Managed(TokenSpan).init(allocator);
        defer spans.deinit();
        try self.appendPiecesForFamily(&spans, allocator, text, 0);
        return allocator.dupe(TokenSpan, spans.items);
    }

    pub fn encodePieceAlloc(self: *Tokenizer, allocator: std.mem.Allocator, piece: []const u8, base_offset: usize) ![]TokenSpan {
        _ = std.unicode.Utf8View.init(piece) catch return error.InvalidUtf8;
        var spans = std.array_list.Managed(TokenSpan).init(allocator);
        defer spans.deinit();
        try self.appendPiece(&spans, allocator, piece, base_offset, 0, piece.len);
        return allocator.dupe(TokenSpan, spans.items);
    }

    pub fn encodeSingleToken(self: *Tokenizer, bytes: []const u8) !u32 {
        return try self.tokenIdForBytes(bytes);
    }

    pub fn decodeBytesAlloc(self: *Tokenizer, allocator: std.mem.Allocator, ids: []const u32) ![]u8 {
        var total: usize = 0;
        for (ids) |id| {
            const bytes = self.bytesForId(id) orelse return error.TokenNotFound;
            total += bytes.len;
        }

        const out = try allocator.alloc(u8, total);
        var cursor: usize = 0;
        for (ids) |id| {
            const bytes = self.bytesForId(id) orelse return error.TokenNotFound;
            @memcpy(out[cursor .. cursor + bytes.len], bytes);
            cursor += bytes.len;
        }
        return out;
    }

    pub fn specialIdForName(self: *Tokenizer, name: []const u8) ?u32 {
        return self.special_tokens.get(name);
    }
};

fn makeTokenBuffer(allocator: std.mem.Allocator, spans: []TokenSpan) !TokenBuffer {
    const items = try allocator.dupe(TokenSpan, spans);
    return .{ .items = items.ptr, .len = items.len };
}

fn makeByteBuffer(allocator: std.mem.Allocator, bytes: []u8) !ByteBuffer {
    const copy = try allocator.dupe(u8, bytes);
    return .{ .items = copy.ptr, .len = copy.len };
}

pub export fn zig_tiktoken_open(name_ptr: [*]const u8, name_len: usize, out_handle: *?*Tokenizer) c_int {
    const name = name_ptr[0..name_len];
    const handle = std.heap.page_allocator.create(Tokenizer) catch return code(.alloc_failed);
    handle.* = Tokenizer.init(std.heap.page_allocator, name) catch |err| {
        std.heap.page_allocator.destroy(handle);
        return switch (err) {
            error.UnknownEncoding => code(.unknown_encoding),
            error.OutOfMemory => code(.alloc_failed),
            else => code(.invalid_input),
        };
    };
    out_handle.* = handle;
    return code(.ok);
}

pub export fn zig_tiktoken_close(handle: ?*Tokenizer) void {
    if (handle) |ptr| {
        ptr.deinit();
        std.heap.page_allocator.destroy(ptr);
    }
}

pub export fn zig_tiktoken_encode_ordinary(handle: ?*Tokenizer, text_ptr: [*]const u8, text_len: usize, out: *TokenBuffer) c_int {
    const tokenizer = handle orelse return code(.invalid_input);
    const text = text_ptr[0..text_len];
    const spans = tokenizer.encodeOrdinaryAlloc(std.heap.page_allocator, text) catch |err| {
        return switch (err) {
            error.InvalidUtf8 => code(.invalid_utf8),
            error.TokenNotFound => code(.token_not_found),
            error.OutOfMemory => code(.alloc_failed),
            else => code(.invalid_input),
        };
    };
    out.items = spans.ptr;
    out.len = spans.len;
    return code(.ok);
}

pub export fn zig_tiktoken_encode_piece(handle: ?*Tokenizer, text_ptr: [*]const u8, text_len: usize, out: *TokenBuffer) c_int {
    const tokenizer = handle orelse return code(.invalid_input);
    const text = text_ptr[0..text_len];
    const spans = tokenizer.encodePieceAlloc(std.heap.page_allocator, text, 0) catch |err| {
        return switch (err) {
            error.InvalidUtf8 => code(.invalid_utf8),
            error.TokenNotFound => code(.token_not_found),
            error.OutOfMemory => code(.alloc_failed),
        };
    };
    out.items = spans.ptr;
    out.len = spans.len;
    return code(.ok);
}

pub export fn zig_tiktoken_free_tokens(handle: ?*Tokenizer, buffer: *TokenBuffer) void {
    _ = handle;
    if (buffer.items) |items| {
        std.heap.page_allocator.free(items[0..buffer.len]);
        buffer.items = null;
        buffer.len = 0;
    }
}

pub export fn zig_tiktoken_encode_single_token(handle: ?*Tokenizer, text_ptr: [*]const u8, text_len: usize, out_id: *u32) c_int {
    const tokenizer = handle orelse return code(.invalid_input);
    const text = text_ptr[0..text_len];
    const id = tokenizer.encodeSingleToken(text) catch |err| {
        return switch (err) {
            error.TokenNotFound => code(.token_not_found),
        };
    };
    out_id.* = id;
    return code(.ok);
}

pub export fn zig_tiktoken_decode_bytes(handle: ?*Tokenizer, ids_ptr: [*]const u32, ids_len: usize, out: *ByteBuffer) c_int {
    const tokenizer = handle orelse return code(.invalid_input);
    const ids = ids_ptr[0..ids_len];
    const bytes = tokenizer.decodeBytesAlloc(std.heap.page_allocator, ids) catch |err| {
        return switch (err) {
            error.TokenNotFound => code(.token_not_found),
            else => code(.invalid_input),
        };
    };
    out.items = bytes.ptr;
    out.len = bytes.len;
    return code(.ok);
}

pub export fn zig_tiktoken_free_bytes(handle: ?*Tokenizer, buffer: *ByteBuffer) void {
    _ = handle;
    if (buffer.items) |items| {
        std.heap.page_allocator.free(items[0..buffer.len]);
        buffer.items = null;
        buffer.len = 0;
    }
}

pub export fn zig_tiktoken_special_token_id(handle: ?*Tokenizer, name_ptr: [*]const u8, name_len: usize, out_id: *u32) c_int {
    const tokenizer = handle orelse return code(.invalid_input);
    const name = name_ptr[0..name_len];
    if (tokenizer.specialIdForName(name)) |id| {
        out_id.* = id;
        return code(.ok);
    }
    return code(.token_not_found);
}

test "basic gpt2 tokenization" {
    var tokenizer = try Tokenizer.init(std.testing.allocator, "gpt2");
    defer tokenizer.deinit();
    const spans = try tokenizer.encodeOrdinaryAlloc(std.testing.allocator, "hello world");
    defer std.testing.allocator.free(spans);
    try std.testing.expect(spans.len > 0);
}

const std = @import("std");

const assert = std.debug.assert;

pub const TwoBuffer = @import("TwoBuffer.zig");

pub const bytes = @import("bytes.zig").bytes;
pub const patternMatchBytes = @import("bytes.zig").patternMatchBytes;

pub fn Reference(comptime T: type) type {
    return struct {
        value: T,
        size: usize,
        pub const ValueType = T;
    };
}

fn GetReferenceValueType(comptime T: type) ?type {
    const info = @typeInfo(T);
    if (info != .@"struct" or info.@"struct".is_tuple) return null;
    for (info.@"struct".decls) |decl| {
        const DeclType = @TypeOf(@field(T, decl.name));
        if (DeclType == type and Reference(@field(T, decl.name)) == T) return @field(T, decl.name);
    }
    return null;
}

/// Appends the `value` to the end of the buffer, creates a reference to it,
/// reserves `size` amount of bytes in the current place.
pub fn reference(size: usize, value: anytype) Reference(@TypeOf(bytes(value))) {
    return .{ .value = bytes(value), .size = size };
}

pub const UseReference = union(enum) {
    last: void,
    at: usize,
    backword: usize,
};

/// Reference the reference? Searches and re-uses specific reference or creates one if it doesn't find it.
pub fn useReference(use: anytype) UseReference {
    const UseType = @TypeOf(use);
    const info = @typeInfo(UseType);
    if (info == .int or info == .comptime_int) return UseReference{ .at = use };
    if (info == .enum_literal) return use;
    if (info == .@"struct" and info.@"struct".fields.len == 1) {
        const field = info.@"struct".fields[0];
        return @unionInit(UseReference, field.name, @field(use, field.name));
    }
    @compileError("Please provide enum literal or usize value.");
}

pub fn ReusableReferenceOrCreate(comptime T: type) type {
    return struct {
        use: usize,
        reference: Reference(T),
        pub const RefValueType = T;
    };
}

fn GetReusableReferenceOrCreateValueType(comptime T: type) ?type {
    const info = @typeInfo(T);
    if (info != .@"struct" or info.@"struct".is_tuple) return null;
    for (info.@"struct".decls) |decl| {
        const DeclType = @TypeOf(@field(T, decl.name));
        if (DeclType == type and ReusableReferenceOrCreate(@field(T, decl.name)) == T) return @field(T, decl.name);
    }
    return null;
}

pub fn reusableReferenceOrCreate(use: usize, size: usize, value: anytype) ReusableReferenceOrCreate(@TypeOf(bytes(value))) {
    return .{ .use = use, .reference = reference(size, value) };
}

pub const ReusableReference = struct {
    use: usize,
};

pub fn reusableReference(use: usize) ReusableReference {
    return .{ .use = use };
}

test useReference {
    const ur = useReference(.{ .backword = 69 });
    try std.testing.expectEqual(UseReference{ .backword = 69 }, ur);
}

pub const MarkTag = enum(u8) {
    pos,
    reference,
};

pub const MarkType = union(MarkTag) {
    pos: void,
    reference: UseReference,
};

pub const Mark = struct {
    type: MarkType,
    ident_result: ?*usize,
};

/// Marks specific position or a reference.
pub fn mark(m: anytype, res_ident: ?*usize) Mark {
    const MType = @TypeOf(m);
    const info = @typeInfo(MType);
    if (info == .enum_literal) return .{ .type = m, .ident_result = res_ident };
    if (info == .@"struct" and info.@"struct".fields.len == 1) {
        const field = info.@"struct".fields[0];
        return .{ .type = @unionInit(MarkType, field.name, @field(m, field.name)), .ident_result = res_ident };
    }
    @compileError("Please provide enum literal or `Mark` initialization value.");
}

test mark {
    var ident: usize = 0;
    const m = mark(.{ .reference = UseReference{ .at = 10 } }, &ident);
    try std.testing.expectEqual(Mark{ .type = .{ .reference = UseReference{ .at = 10 } }, .ident_result = &ident }, m);
}

pub const ReferenceData = struct {
    block_idx: usize,
    offset: usize,
    size: usize,
    // TODO: Turn value buffer into blocks format too.
    /// value offset from this reference
    value_offset: usize,

    /// Calculates the offset to the value in the final buffer.
    pub fn calculateValueOffset(self: ReferenceData) usize {
        return self.offset + self.size + self.value_offset;
    }
};

pub const Marked = union(enum) {
    pos: struct {
        block_id: usize,
        offset: usize,
    },
    reference: struct {
        idx: usize,
    },
};

/// Responsible for freeing the backing MultiArrayList, and doesn't expose any mutable interface.
fn ReadOnlyMultiArrayList(comptime T: type) type {
    return struct {
        allocator: std.mem.Allocator,
        slice: MultiArrayList.Slice,
        const MultiArrayList = std.MultiArrayList(T);

        const Self = @This();

        fn init(allocator: std.mem.Allocator, ma: MultiArrayList) Self {
            return .{ .allocator = allocator, .slice = ma.slice() };
        }

        pub fn len(self: Self) usize {
            return self.slice.len;
        }

        pub fn get(self: Self, index: usize) Marked {
            return self.slice.get(index);
        }

        pub fn getLast(self: Self) Marked {
            return self.slice.get(self.len() - 1);
        }

        pub fn deinit(self: Self) void {
            var ma_list = self.slice.toMultiArrayList();
            ma_list.deinit(self.allocator);
        }
    };
}

pub const ReadOnlyMarkers = ReadOnlyMultiArrayList(Marked);

/// Returned after calling `commit`
pub const CommittedResult = struct {
    buffer: TwoBuffer.OwnedBuffer,
    refrences: std.ArrayList(ReferenceData),
    markers: ReadOnlyMarkers,
    reserved_offset: usize,

    pub fn deinit(self: CommittedResult) void {
        self.refrences.deinit();
        self.markers.deinit();
        self.buffer.deinit(self.markers.allocator);
    }
};

/// Returned after calling `commitOwned`
pub const CommittedOwnedResult = struct {
    buffer: []u8,
    refrences: std.ArrayList(ReferenceData),
    markers: ReadOnlyMarkers,
    reserved_offset: usize,
};

const WriteTag = enum {
    reference,
    slice,
};

pub const Write = struct {
    tag: WriteTag,
    offset: usize,
    size: usize,
    extra_data: usize = 0,
};

// TODO: Recalculate size by accumulating from the `writes`, add ability to update block from
// `AsmPatcherBuffer`
pub const Block = struct {
    size: usize,
    writes: std.MultiArrayList(Write),
};

pub const AsmPatchBuffer = struct {
    allocator: std.mem.Allocator,
    buffer: TwoBuffer,
    references: std.ArrayList(ReferenceData),
    // TODO: remove it merged with other?
    reusable_refs: std.ArrayList(usize),
    markers: std.MultiArrayList(Marked),
    blocks: std.ArrayList(Block),
    original: []const u8,
    /// Current reading position from `original`.
    pos: usize = 0,

    pub fn init(allocator: std.mem.Allocator, original: []const u8) AsmPatchBuffer {
        return .{
            .allocator = allocator,
            .buffer = .init(allocator),
            .references = .init(allocator),
            .reusable_refs = .init(allocator),
            .markers = .empty,
            .blocks = .init(allocator),
            .original = original,
        };
    }

    fn deinitBlocks(self: *AsmPatchBuffer) void {
        for (self.blocks.items) |*block| {
            block.writes.deinit(self.allocator);
        }
        self.blocks.deinit();
    }

    pub fn deinit(self: *AsmPatchBuffer) void {
        self.buffer.deinit();
        self.references.deinit();
        self.reusable_refs.deinit();
        self.markers.deinit(self.allocator);
        self.deinitBlocks();
    }

    pub fn currentLenWith(self: AsmPatchBuffer, reserve_size: usize) usize {
        return self.buffer.a_len + self.buffer.b_len + reserve_size;
    }

    /// Gives an estimation of the reference's offsets from current overall buffer state.
    pub fn estimateReferenceOffsets(self: AsmPatchBuffer, ref_idx: usize, reserve_size: usize) ReferenceData {
        var ref = self.references.items[ref_idx];
        var block_offset: usize = 0;
        for (self.blocks.items, 0..) |block, i| {
            if (i == ref.block_idx) break;
            block_offset += block.size;
        }
        ref.offset += block_offset;
        const new_values_start_offset = self.buffer.len(.a) + reserve_size;
        const new_bytes_added = new_values_start_offset - (ref.offset + ref.size);
        return .{
            .block_idx = 0,
            .offset = ref.offset,
            .size = ref.size,
            .value_offset = ref.value_offset + new_bytes_added,
        };
    }

    /// Gets the `Marked.pos` at `marker_idx` relative to current buffer state.
    pub fn getMarkerPos(self: AsmPatchBuffer, marker_idx: usize) usize {
        const marker = self.markers.get(marker_idx);
        assert(marker == .pos);
        var block_offset: usize = 0;
        for (self.blocks.items, 0..) |block, i| {
            if (i == marker.pos.block_id) break;
            block_offset += block.size;
        }
        return block_offset + marker.pos.offset;
    }

    /// `size` must not exceed it's owner block size and `offset` must be relative to
    /// it's owner block not to the full buffer.
    // TODO: Probably won't gonna need after we implement block isolated update?
    pub fn updateReference(self: *AsmPatchBuffer, ref_idx: usize, size: usize, offset: usize) void {
        const ref = &self.references.items[ref_idx];
        assert(size <= self.blocks.items[ref.block_idx].size);
        ref.size = size;
        ref.offset = offset;
    }

    /// Copies [pos, pos+size) range, advances pos by size.
    pub fn copy(self: *AsmPatchBuffer, size: usize) !void {
        assert(self.pos < self.original.len);
        const slice = self.original[self.pos .. self.pos + size];
        var block: Block = .{
            .size = slice.len,
            .writes = .empty,
        };
        try self.buffer.appendSlice(.a, slice);

        try block.writes.append(self.allocator, .{
            .tag = .slice,
            .offset = 0,
            .size = slice.len,
        });
        try self.blocks.append(block);

        self.pos += size;
    }

    /// Copies [pos, offset) range, advances pos by total range len.
    ///
    /// `offset` must be >= pos and < `original_buffer.len`
    pub fn copyUntilOffset(self: *AsmPatchBuffer, offset: usize) !void {
        // assert(offset < self.original.len and self.pos >= offset);
        const size = offset - self.pos;
        return self.copy(size);
    }

    /// Copies rest of the original buffer's content.
    pub fn copyRest(self: *AsmPatchBuffer) !void {
        if (self.pos >= self.original.len) return;
        return self.copy(self.original[self.pos..].len);
    }

    /// Writes to the `buffer`, doesn't advance pos.
    pub fn write(self: *AsmPatchBuffer, value: anytype) !void {
        try self.writeImpl(value);
    }

    /// Same as `write` but advances pos by `size`, so replacing [pos, size) of the original.
    pub fn replace(self: *AsmPatchBuffer, size: usize, value: anytype) !void {
        try self.write(value);
        self.pos += size;
    }

    /// Gets a `Block` ptr within the specified range, the ptr might get invalid when
    /// the blocks list is updated.
    pub fn getBlockPtrWithin(self: *AsmPatchBuffer, start: usize, len: usize) ?*Block {
        var block_offset: usize = 0;
        var block_id: usize = 0;
        var found_block: ?*Block = null;
        for (self.blocks.items, 0..) |*block, i| {
            if (block_offset >= start and start + len <= block_offset + block.size) {
                found_block = block;
                block_id = i;
                break;
            }
            block_offset += block.size;
        }
        return found_block;
    }

    pub fn replaceRange(
        self: *AsmPatchBuffer,
        start: usize,
        len: usize,
        new_items: []const u8,
    ) !void {
        return self.buffer.replaceRange(.a, start, len, new_items);
    }

    pub fn skip(self: *AsmPatchBuffer, size: usize) void {
        self.pos += size;
    }

    /// Merges replaced buffer content and new values buffer but `reserve_size`
    /// amount of space is reserved before merging, `reserve_size` can be 0.
    /// Updates references offsets by accounting new contents of the `buffer`.
    /// Transfers necessary fields to `CommittedPatchBuffer` instance.
    /// Safe to call `deinit` but not necessary.
    pub fn commit(self: *AsmPatchBuffer, reserve_size: usize) !CommittedResult {
        const reserved_offset = self.buffer.len(.a);

        const new_values_start_offset = reserved_offset + reserve_size;
        const buffer = try self.buffer.toOwned(reserve_size);

        const block_offsets = try self.allocator.alloc(usize, self.blocks.items.len);
        defer self.allocator.free(block_offsets);

        var current_offset: usize = 0;
        // TODO: Recalculate block size within it's writes?
        for (self.blocks.items, 0..) |*block, i| {
            // const ws = block.writes.slice();
            // for (0..ws.len) |i| {
            //     const w = ws.get(i);
            //     if (w.tag == .reference) {
            //         const ref = &self.references.items[w.extra_data];
            //         ref.offset += current_offset;
            //         const new_bytes_added = new_values_start_offset - (ref.offset + ref.size);
            //         ref.value_offset += new_bytes_added;
            //     }
            // }
            block_offsets[i] = current_offset;
            current_offset += block.size;
        }

        for (self.references.items) |*ref| {
            // ref = [reference_offset + reference_size]
            // [before ref][ref][after ref][...reserved...][start of new values][ref value's offset]
            // so in the merged `buffer` [ref value's offset] = [after ref][...reserved...][start of new values]
            ref.offset += block_offsets[ref.block_idx];
            const new_bytes_added = new_values_start_offset - (ref.offset + ref.size);
            ref.value_offset += new_bytes_added;
        }

        const committed: CommittedResult = .{
            .buffer = buffer,
            .refrences = self.references,
            .reserved_offset = reserved_offset,
            .markers = .init(self.allocator, self.markers),
        };
        self.deinitAfterCommit();

        return committed;
    }

    /// Same as `commit` but the result is owned by the caller has to deinit everything by the caller.
    pub fn commitOwned(self: *AsmPatchBuffer, reserve_size: usize) !CommittedOwnedResult {
        const reserved_offset = self.buffer.len(.a);

        const new_values_start_offset = reserved_offset + reserve_size;
        const buffer = try self.buffer.toOwnedSlice(reserve_size);

        const block_offsets = try self.allocator.alloc(usize, self.blocks.items.len);
        defer self.allocator.free(block_offsets);

        var current_offset: usize = 0;
        // TODO: Recalculate block size within it's writes?
        for (self.blocks.items, 0..) |*block, i| {
            // const ws = block.writes.slice();
            // for (0..ws.len) |i| {
            //     const w = ws.get(i);
            //     if (w.tag == .reference) {
            //         const ref = &self.references.items[w.extra_data];
            //         ref.offset += current_offset;
            //         const new_bytes_added = new_values_start_offset - (ref.offset + ref.size);
            //         ref.value_offset += new_bytes_added;
            //     }
            // }
            block_offsets[i] = current_offset;
            current_offset += block.size;
        }

        for (self.references.items) |*ref| {
            // ref = [reference_offset + reference_size]
            // [before ref][ref][after ref][...reserved...][start of new values][ref value's offset]
            // so in the merged `buffer` [ref value's offset] = [after ref][...reserved...][start of new values]
            ref.offset += block_offsets[ref.block_idx];
            const new_bytes_added = new_values_start_offset - (ref.offset + ref.size);
            ref.value_offset += new_bytes_added;
        }

        const committed: CommittedOwnedResult = .{
            .buffer = buffer,
            .refrences = self.references,
            .reserved_offset = reserved_offset,
            .markers = .init(self.allocator, self.markers),
        };
        self.deinitAfterCommit();

        return committed;
    }

    fn deinitAfterCommit(self: *AsmPatchBuffer) void {
        self.reusable_refs.deinit();
        self.deinitBlocks();
        self.* = .init(self.allocator, self.original);
    }

    /// Copies the rest of the original buffer from current `pos` and performs `commit`.
    pub fn copyRestAndCommit(self: *AsmPatchBuffer, reserve_size: usize) !CommittedResult {
        try self.copyRest();
        return self.commit(reserve_size);
    }

    /// Copies the rest of the original buffer from current `pos` and performs `commitOwned`.
    pub fn copyRestAndCommitOwned(self: *AsmPatchBuffer, reserve_size: usize) !CommittedOwnedResult {
        try self.copyRest();
        return self.commitOwned(reserve_size);
    }

    fn getReferenceIdx(self: *AsmPatchBuffer, ur: UseReference) usize {
        switch (ur) {
            .at => |at| {
                assert(at < self.references.items.len);
                return at;
            },
            .last => {
                assert(self.references.items.len > 0);
                return self.references.items.len - 1;
            },
            .backword => |back_by| {
                assert(self.references.items.len > back_by);
                return self.references.items.len - 1 - back_by;
            },
        }
    }

    fn getReferenceOrNull(self: AsmPatchBuffer, ur: UseReference) ?usize {
        switch (ur) {
            .at => |at| {
                if (at >= self.references.items.len) {
                    return null;
                }
                return at;
            },
            .last => {
                if (self.references.items.len == 0) return null;
                return self.references.items.len - 1;
            },
            .backword => |back_by| {
                if (self.references.items.len <= back_by) return null;
                return self.references.items.len - 1 - back_by;
            },
        }
    }

    fn getReusableReference(self: AsmPatchBuffer, idx: usize) ?usize {
        if (idx >= self.reusable_refs.items.len) return null;
        const at = self.reusable_refs.items[idx];
        return self.getReferenceOrNull(UseReference{ .at = at });
    }

    fn mark(self: *AsmPatchBuffer, mark_type: MarkType, current_block: usize, local_offset: usize) !usize {
        const ident = self.markers.len;
        switch (mark_type) {
            .pos => {
                try self.markers.append(self.allocator, .{
                    .pos = .{
                        .block_id = current_block,
                        .offset = local_offset,
                    },
                });
            },
            .reference => |ur| {
                const ref_idx = self.getReferenceIdx(ur);
                try self.markers.append(self.allocator, .{ .reference = .{ .idx = ref_idx } });
            },
        }
        return ident;
    }

    const getU8Slice = struct {
        inline fn func(comptime T: type, v: T, comptime var_pos: comptime_int) []const u8 {
            if (T == []const u8) {
                return v;
            }
            const field_type_info = @typeInfo(T);
            switch (field_type_info) {
                .array => |array| {
                    if (array.child == u8) {
                        const value_as_bytes: []const u8 = &v;
                        return value_as_bytes;
                    }
                },
                .pointer => |pointer| {
                    if (pointer.child == u8 and pointer.size == .slice) {
                        const value_as_bytes: []const u8 = v;
                        return value_as_bytes;
                    }

                    if (pointer.sentinel()) |sentinel| {
                        if (sentinel == 0 and pointer.child == u8) {
                            return std.mem.span(v);
                        }
                    }

                    const child_info = @typeInfo(pointer.child);
                    if (child_info == .array and child_info.array.child == u8) {
                        const value_as_bytes: []const u8 = v;
                        return value_as_bytes;
                    }
                },
                else => {},
            }

            @compileError("Only expected []const u8(coercible), " ++
                @typeName(Reference([]const u8)) ++ ", " ++ @typeName(UseReference) ++
                " types, found: '" ++ @typeName(T) ++
                "', positon: " ++ std.fmt.comptimePrint("{}", .{var_pos}));
        }
    }.func;

    inline fn writeImpl(self: *AsmPatchBuffer, tuple: anytype) !void {
        var block: Block = .{
            .size = 0,
            .writes = .empty,
        };
        const block_id = self.blocks.items.len;
        block.size = try self.writeAsBlock(&block, block_id, tuple);
        try self.blocks.append(block);
    }

    // TODO: Add some way to isolate the written reference values with in the block?
    inline fn writeAsBlock(self: *AsmPatchBuffer, block: *Block, block_id: usize, tuple: anytype) !usize {
        const TupleType = @TypeOf(tuple);
        const info = @typeInfo(TupleType);

        if (info != .@"struct" or !info.@"struct".is_tuple) {
            @compileError("Need tuple struct type.");
        }

        var local_offset: usize = 0;

        const struct_info = info.@"struct";
        inline for (struct_info.fields, 0..) |field, i| {
            const FieldType = field.type;
            const value = tuple[i];

            if (GetReferenceValueType(FieldType)) |ValueType| {
                const value_as_slice: []const u8 = getU8Slice(ValueType, value.value, i);
                try self.references.append(.{
                    .block_idx = block_id,
                    .offset = local_offset,
                    .size = value.size,
                    .value_offset = self.buffer.len(.b),
                });

                try block.writes.append(self.allocator, .{
                    .tag = .reference,
                    .offset = local_offset,
                    .size = value.size,
                    .extra_data = self.references.items.len - 1,
                });

                try self.buffer.appendNTimes(.a, 0x00, value.size);
                try self.buffer.appendSlice(.b, value_as_slice);

                local_offset += value.size;
            } else if (FieldType == UseReference) {
                var ref = self.references.items[self.getReferenceIdx(value)];
                ref.offset = local_offset;
                ref.block_idx = block_id;
                try self.references.append(ref);

                try block.writes.append(self.allocator, .{
                    .tag = .reference,
                    .offset = local_offset,
                    .size = ref.size,
                    .extra_data = self.references.items.len - 1,
                });

                try self.buffer.appendNTimes(.a, 0x00, ref.size);
            } else if (GetReusableReferenceOrCreateValueType(FieldType)) |RefValueType| {
                if (self.getReusableReference(value.use)) |idx| {
                    var ref = self.references.items[idx];
                    ref.offset = local_offset;
                    ref.block_idx = block_id;
                    try self.references.append(ref);

                    try block.writes.append(self.allocator, .{
                        .tag = .reference,
                        .offset = local_offset,
                        .size = ref.size,
                        .extra_data = self.references.items.len - 1,
                    });

                    try self.buffer.appendNTimes(.a, 0x00, ref.size);
                    local_offset += ref.size;
                } else {
                    const value_as_slice: []const u8 = getU8Slice(RefValueType, value.reference.value, i);

                    const ref_id = self.references.items.len;
                    try self.references.append(.{
                        .block_idx = block_id,
                        .offset = local_offset,
                        .size = value.reference.size,
                        .value_offset = self.buffer.len(.b),
                    });
                    try self.reusable_refs.append(ref_id);

                    try block.writes.append(self.allocator, .{
                        .tag = .reference,
                        .offset = local_offset,
                        .size = value.reference.size,
                        .extra_data = self.references.items.len - 1,
                    });

                    try self.buffer.appendNTimes(.a, 0x00, value.reference.size);
                    try self.buffer.appendSlice(.b, value_as_slice);

                    local_offset += value.reference.size;
                }
            } else if (FieldType == ReusableReference) {
                const idx = self.getReusableReference(value.use) orelse return error.ReusableRefNotFound;
                var ref = self.references.items[idx];
                ref.offset = local_offset;
                ref.block_idx = block_id;
                try self.references.append(ref);

                try block.writes.append(self.allocator, .{
                    .tag = .reference,
                    .offset = local_offset,
                    .size = ref.size,
                    .extra_data = self.references.items.len - 1,
                });

                try self.buffer.appendNTimes(.a, 0x00, ref.size);
                local_offset += ref.size;
            } else if (FieldType == Mark) {
                const ident = try self.mark(value.type, block_id, local_offset);
                if (value.ident_result) |ident_result| {
                    ident_result.* = ident;
                }
            } else {
                const value_as_slice = getU8Slice(FieldType, value, i);
                try self.buffer.appendSlice(.a, value_as_slice);

                try block.writes.append(self.allocator, .{
                    .tag = .slice,
                    .offset = local_offset,
                    .size = value_as_slice.len,
                });

                local_offset += value_as_slice.len;
            }
        }

        return local_offset;
    }
};

test "AsmPatchBuffer basic" {
    const orig: []const u8 = &.{
        0x0f, 0x84, 0xfb, 0x00, 0x00, 0x00, // je 0xfb ; jmp rel32
        0x0f, 0x85, 0xfb, 0x00, 0x00, 0x00, // jne 0xfb ; jmp rel32
        0x74, 0x05, // je 5 ; jmp rel8
        0x75, 0xfB, // jne -5 ; jmp rel8
    };
    var pb = AsmPatchBuffer.init(std.testing.allocator, orig);
    defer pb.deinit();

    try pb.copy(2);
    const value1: usize = 0x6969;
    try pb.replace(4, .{
        bytes(.{ 0x60, 0x70 }),
        reference(2, .{value1}),
    });
    try pb.replace(4, .{
        bytes(.{ 0x61, 0x71 }),
        reference(2, .{ 0xC, 0xD }),
        mark(.pos, null),
    });
    try pb.copyRest();

    const committed = try pb.commit(14);
    defer committed.deinit();

    try std.testing.expectEqual(16, committed.reserved_offset);
    try std.testing.expectEqual(16 + 14, committed.refrences.items[0].calculateValueOffset());
    try std.testing.expectEqual(16 + 14 + @sizeOf(usize), committed.refrences.items[1].calculateValueOffset());
    try std.testing.expectEqualSlices(u8, &.{ 0xC, 0xD }, committed.buffer.items[committed.refrences.items[1].calculateValueOffset()..]);
    try std.testing.expectEqual(orig.len + 14 + 2 + @sizeOf(usize), committed.buffer.items.len);
    try std.testing.expectEqual(10 + 14, committed.refrences.items[0].value_offset);
}

test "AsmPatchBuffer basic owned" {
    const orig: []const u8 = &.{
        0x0f, 0x84, 0xfb, 0x00, 0x00, 0x00, // je 0xfb ; jmp rel32
        0x0f, 0x85, 0xfb, 0x00, 0x00, 0x00, // jne 0xfb ; jmp rel32
        0x74, 0x05, // je 5 ; jmp rel8
        0x75, 0xfB, // jne -5 ; jmp rel8
    };
    var pb = AsmPatchBuffer.init(std.testing.allocator, orig);
    defer pb.deinit();

    try pb.copy(2);
    const value1: usize = 0x6969;
    try pb.replace(4, .{
        bytes(.{ 0x60, 0x70 }),
        reference(2, .{value1}),
    });
    try pb.replace(4, .{
        bytes(.{ 0x61, 0x71 }),
        reference(2, .{ 0xC, 0xD }),
        mark(.pos, null),
    });
    try pb.copyRest();

    const committed = try pb.commitOwned(14);
    defer {
        committed.markers.deinit();
        committed.refrences.deinit();
        std.testing.allocator.free(committed.buffer);
    }

    try std.testing.expectEqual(16, committed.reserved_offset);
    try std.testing.expectEqual(16 + 14, committed.refrences.items[0].calculateValueOffset());
    try std.testing.expectEqual(16 + 14 + @sizeOf(usize), committed.refrences.items[1].calculateValueOffset());
    try std.testing.expectEqualSlices(u8, &.{ 0xC, 0xD }, committed.buffer[committed.refrences.items[1].calculateValueOffset()..]);
    try std.testing.expectEqual(orig.len + 14 + 2 + @sizeOf(usize), committed.buffer.len);
    try std.testing.expectEqual(10 + 14, committed.refrences.items[0].value_offset);
}

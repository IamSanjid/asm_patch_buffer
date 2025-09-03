const std = @import("std");

const assert = std.debug.assert;

allocator: std.mem.Allocator,
bytes: [*]u8 = undefined,
a_len: usize = 0,
a_cap: usize = 0,
b_len: usize = 0,
b_cap: usize = 0,

const expected_gap_in_between = 16;
const a_portion = 0.65;
const b_portion = 1 - a_portion;
const chunk_size = 256;
const init_a_cap: usize = std.mem.alignBackward(usize, (chunk_size - expected_gap_in_between) * a_portion, @sizeOf(usize));
const init_b_cap: usize = std.mem.alignBackward(usize, (chunk_size - expected_gap_in_between) * b_portion, @sizeOf(usize));
const gap_in_between = chunk_size - init_a_cap - init_b_cap;

const Unmanaged = std.ArrayListUnmanaged(u8);

const TwoBuffer = @This();

pub fn init(allocator: std.mem.Allocator) TwoBuffer {
    return .{ .allocator = allocator };
}

pub fn deinit(self: TwoBuffer) void {
    const capacity = self.a_cap + gap_in_between + self.b_cap;
    if (self.a_cap + self.b_cap == 0) return;
    var unmanaged = Unmanaged{ .items = self.bytes[0..0], .capacity = capacity };
    unmanaged.deinit(self.allocator);
}

pub fn len(self: TwoBuffer, comptime which: @Type(.enum_literal)) usize {
    if (which == .a) {
        return self.a_len;
    } else if (which == .b) {
        return self.b_len;
    } else {
        @compileError("`to` must be `.a` or `.b");
    }
}

fn merge(self: *TwoBuffer, reserve_gap: usize) !usize {
    // [a][a_extra][gap][b][b_extra]
    // a_cap = [a] + [a_extra]
    // b_cap = [b] + [b_extra]
    var final_size: usize = 0;
    if (reserve_gap > gap_in_between) {
        const need_extra = reserve_gap - gap_in_between;
        final_size = self.a_len + gap_in_between + need_extra + self.b_len;
        // [a][need_extra][a_extra - need_extra][gap][b_cap]
        _ = try self.addManyAsSlice(.a, need_extra);
        const b_end = self.a_cap + gap_in_between + self.b_len;
        // [a][need_extra][gap][b]
        @memmove(self.bytes[self.a_len..], self.bytes[self.a_cap..b_end]);
    } else {
        const need_less = gap_in_between - reserve_gap;
        const b_start = self.a_cap + gap_in_between;
        const b_end = self.a_cap + gap_in_between + self.b_len;
        // [gap_less] = [gap - need_less]
        // [a_cap][gap_less][b]
        @memmove(self.bytes[self.a_cap + gap_in_between - need_less ..], self.bytes[b_start..b_end]);
        // [a][gap_less][b]
        @memmove(self.bytes[self.a_len..], self.bytes[self.a_cap..b_end]);
        final_size = self.a_len + gap_in_between - need_less + self.b_len;
    }

    return final_size;
}

pub const OwnedBuffer = struct {
    capacity: usize,
    items: []u8,

    pub fn deinit(self: OwnedBuffer, allocator: std.mem.Allocator) void {
        allocator.free(self.items.ptr[0..self.capacity]);
    }
};

pub fn toOwned(self: *TwoBuffer, reserved_gap: usize) !OwnedBuffer {
    const final_size = try self.merge(reserved_gap);
    const capacity = self.a_cap + gap_in_between + self.b_cap;
    self.a_cap = 0;
    self.b_cap = 0;
    return .{
        .capacity = capacity,
        .items = self.bytes[0..final_size],
    };
}

pub fn toOwnedSlice(self: *TwoBuffer, reserved_gap: usize) ![]u8 {
    const final_size = try self.merge(reserved_gap);

    const capacity = self.a_cap + gap_in_between + self.b_cap;
    var unmanaged = Unmanaged{ .items = self.bytes[0..capacity], .capacity = capacity };
    unmanaged.shrinkAndFree(self.allocator, final_size);

    self.a_cap = 0;
    self.b_cap = 0;
    return unmanaged.items.ptr[0..final_size];
}

pub fn getBuffer(self: TwoBuffer, comptime which: @Type(.enum_literal)) []u8 {
    if (which == .a) {
        return self.bytes[0..self.a_len];
    } else if (which == .b) {
        return self.bytes[self.a_cap + gap_in_between .. self.a_cap + gap_in_between + self.b_len];
    } else {
        @compileError("`to` must be `.a` or `.b");
    }
}

pub fn addManyAsSlice(self: *TwoBuffer, comptime to: @Type(.enum_literal), n: usize) ![]u8 {
    try self.ensureUnusedCapacity(to, n);
    if (to == .a) {
        const new_mem = self.bytes[self.a_len .. self.a_len + n];
        self.a_len += n;
        return new_mem;
    } else if (to == .b) {
        const b_start = self.a_cap + gap_in_between;
        const new_mem = self.bytes[b_start + self.b_len .. b_start + self.b_len + n];
        self.b_len += n;
        return new_mem;
    } else {
        @compileError("`to` must be `.a` or `.b");
    }
}

pub fn appendNTimes(self: *TwoBuffer, comptime to: @Type(.enum_literal), item: u8, n: usize) !void {
    try self.ensureUnusedCapacity(to, n);
    if (to == .a) {
        const new_mem = self.bytes[self.a_len .. self.a_len + n];
        @memset(new_mem, item);
        self.a_len += n;
    } else if (to == .b) {
        const b_start = self.a_cap + gap_in_between;
        const new_mem = self.bytes[b_start + self.b_len .. b_start + self.b_len + n];
        @memset(new_mem, item);
        self.b_len += n;
    } else {
        @compileError("`to` must be `.a` or `.b");
    }
}

pub fn appendSlice(self: *TwoBuffer, comptime to: @Type(.enum_literal), slice: []const u8) !void {
    try self.ensureUnusedCapacity(to, slice.len);

    if (to == .a) {
        const new_mem = self.bytes[self.a_len .. self.a_len + slice.len];
        @memcpy(new_mem, slice);
        self.a_len += slice.len;
    } else if (to == .b) {
        const b_start = self.a_cap + gap_in_between;
        const new_mem = self.bytes[b_start + self.b_len .. b_start + self.b_len + slice.len];
        @memcpy(new_mem, slice);
        self.b_len += slice.len;
    } else {
        @compileError("`to` must be `.a` or `.b");
    }
}

pub fn insertSlice(self: *TwoBuffer, comptime to: @Type(.enum_literal), index: usize, slice: []const u8) !void {
    const to_mem = try self.addManyAt(to, index, slice.len);
    @memcpy(to_mem, slice);
}

pub fn replaceRange(
    self: *TwoBuffer,
    comptime of: @Type(.enum_literal),
    rang_start: usize,
    rang_len: usize,
    new_items: []const u8,
) !void {
    if (of == .a) {
        const after_range = rang_start + rang_len;
        const range = self.getBuffer(.a)[rang_start..after_range];
        if (range.len < new_items.len) {
            const first = new_items[0..range.len];
            const rest = new_items[range.len..];
            @memcpy(range[0..first.len], first);
            try self.insertSlice(.a, after_range, rest);
        } else {
            var unmanaged = Unmanaged{ .items = self.getBuffer(.a), .capacity = self.a_cap };
            unmanaged.replaceRangeAssumeCapacity(rang_start, rang_len, new_items);
            self.a_len = unmanaged.items.len;
        }
    } else {
        const after_range = rang_start + rang_len;
        const range = self.getBuffer(.b)[rang_start..after_range];
        if (range.len < new_items.len) {
            const first = new_items[0..range.len];
            const rest = new_items[range.len..];
            @memcpy(range[0..first.len], first);
            try self.insertSlice(.a, after_range, rest);
        } else {
            var unmanaged = Unmanaged{
                .items = self.getBuffer(.b),
                .capacity = self.b_cap,
            };
            unmanaged.replaceRangeAssumeCapacity(rang_start, rang_len, new_items);
            self.b_len = unmanaged.items.len;
        }
    }
}

pub fn addManyAt(self: *TwoBuffer, comptime to: @Type(.enum_literal), index: usize, count: usize) ![]u8 {
    try self.ensureUnusedCapacity(to, count);

    if (to == .a) {
        var unmanaged = Unmanaged{ .items = self.bytes[0..self.a_len], .capacity = self.a_cap };
        const to_mem = unmanaged.addManyAtAssumeCapacity(index, count);
        self.a_len += count;
        return to_mem;
    } else if (to == .b) {
        const b_start = self.a_cap + gap_in_between;
        var unmanaged = Unmanaged{
            .items = self.bytes[b_start .. b_start + self.b_len],
            .capacity = self.b_cap,
        };
        const to_mem = unmanaged.addManyAtAssumeCapacity(index, count);
        self.b_len += count;
        return to_mem;
    } else {
        @compileError("`to` must be `.a` or `.b");
    }
}

fn ensureUnusedCapacity(self: *TwoBuffer, comptime to: @Type(.enum_literal), additional_count: usize) !void {
    const capacity = self.a_cap + gap_in_between + self.b_cap;
    // we're already doing a lot of if else(s) so one more won't gonna matter
    if (self.a_cap + self.b_cap == 0) {
        @branchHint(.unlikely);
        self.bytes = (try self.allocator.alloc(u8, chunk_size)).ptr;
        self.a_cap = init_a_cap;
        self.b_cap = init_b_cap;
        return self.ensureUnusedCapacity(to, additional_count);
    }
    const b_buffer = self.getBuffer(.b);
    const a_buffer = self.getBuffer(.a);

    const to_cap = if (to == .a) self.a_cap else self.b_cap;

    const new_len = self.len(to) + additional_count;
    if (to_cap >= new_len) return;

    const min_capacity = capacity + additional_count * 2;
    const new_capacity = growCapacity(capacity, min_capacity);
    if (capacity > new_capacity) return;

    const gpa = self.allocator;

    const increased_cap = new_capacity - capacity;
    const max_cap_increase = @max(additional_count, increased_cap - additional_count);
    assert(max_cap_increase <= increased_cap);
    if (to == .b) {
        self.b_cap += max_cap_increase;
        self.a_cap += increased_cap - max_cap_increase;
    } else {
        self.a_cap += max_cap_increase;
        self.b_cap += increased_cap - max_cap_increase;
    }

    const new_b_start = self.a_cap + gap_in_between;

    const old_memory = self.bytes[0..capacity];
    if (gpa.remap(old_memory, new_capacity)) |new_memory| {
        @memmove(new_memory[new_b_start .. new_b_start + b_buffer.len], b_buffer);

        self.bytes = new_memory.ptr;
    } else {
        const new_memory = try gpa.alignedAlloc(u8, null, new_capacity);
        // copy a buffer
        @memcpy(new_memory[0..a_buffer.len], a_buffer);
        // copy b buffer
        @memcpy(new_memory[new_b_start .. new_b_start + b_buffer.len], b_buffer);

        gpa.free(old_memory);
        self.bytes = new_memory.ptr;
    }
}

const init_capacity = @as(comptime_int, @max(1, std.atomic.cache_line / @sizeOf(u8)));
fn growCapacity(current: usize, minimum: usize) usize {
    var new = current;
    while (true) {
        new +|= new / 2 + init_capacity;
        if (new >= minimum)
            return new;
    }
}

test "two buffer" {
    const allocator = std.testing.allocator;
    var tb = TwoBuffer.init(allocator);
    defer tb.deinit();

    var expected_a = std.array_list.Aligned(u8, null).empty;
    defer expected_a.deinit(allocator);
    var expected_b = std.array_list.Aligned(u8, null).empty;
    defer expected_b.deinit(allocator);

    try tb.appendSlice(.a, &.{ 0x69, 0x68, 0x67, 0x66 });
    try expected_a.appendSlice(allocator, &.{ 0x69, 0x68, 0x67, 0x66 });

    try tb.appendSlice(.b, &.{ 0x65, 0x64, 0x63 });
    try expected_b.appendSlice(allocator, &.{ 0x65, 0x64, 0x63 });

    try tb.insertSlice(.a, 0, &.{0x70});
    try expected_a.insertSlice(allocator, 0, &.{0x70});

    {
        const a_buf = tb.getBuffer(.a);
        const b_buf = tb.getBuffer(.b);
        try std.testing.expectEqualSlices(u8, &.{ 0x70, 0x69, 0x68, 0x67, 0x66 }, a_buf);
        try std.testing.expectEqualSlices(u8, expected_a.items, a_buf);
        try std.testing.expectEqualSlices(u8, &.{ 0x65, 0x64, 0x63 }, b_buf);
        try std.testing.expectEqualSlices(u8, expected_b.items, b_buf);
    }

    try tb.insertSlice(.a, 2, &.{ 0x71, 0x72, 0x73 });
    try expected_a.insertSlice(allocator, 2, &.{ 0x71, 0x72, 0x73 });
    {
        const a_buf = tb.getBuffer(.a);
        try std.testing.expectEqualSlices(u8, &.{ 0x70, 0x69, 0x71, 0x72, 0x73, 0x68, 0x67, 0x66 }, a_buf);
        try std.testing.expectEqualSlices(u8, expected_a.items, a_buf);
        try std.testing.expectEqualSlices(u8, &.{ 0x65, 0x64, 0x63 }, tb.getBuffer(.b));
        try std.testing.expectEqualSlices(u8, expected_b.items, tb.getBuffer(.b));
    }

    try tb.insertSlice(.b, 2, &.{ 0x65, 0x64, 0x63 });
    try expected_b.insertSlice(allocator, 2, &.{ 0x65, 0x64, 0x63 });
    try std.testing.expectEqualSlices(u8, &.{ 0x65, 0x64, 0x65, 0x64, 0x63, 0x63 }, tb.getBuffer(.b));
    try std.testing.expectEqualSlices(u8, expected_b.items, tb.getBuffer(.b));

    // adding big chunks!
    for (0..1024) |_| {
        try tb.appendSlice(.a, &.{0xAA});
        try expected_a.appendSlice(allocator, &.{0xAA});
        try tb.appendSlice(.b, &.{0xAA});
        try expected_b.appendSlice(allocator, &.{0xAA});
    }
    try std.testing.expectEqualSlices(u8, &.{ 0x70, 0x69, 0x71, 0x72, 0x73, 0x68, 0x67, 0x66 }, tb.getBuffer(.a)[0..8]);
    try std.testing.expectEqualSlices(u8, &.{ 0x65, 0x64, 0x65, 0x64, 0x63, 0x63 }, tb.getBuffer(.b)[0..6]);

    // adding big chunks!
    for (0..4096) |_| {
        try tb.appendSlice(.a, &.{0xAA});
        try expected_a.appendSlice(allocator, &.{0xAA});
        try tb.appendSlice(.b, &.{0xAA});
        try expected_b.appendSlice(allocator, &.{0xAA});
    }
    try std.testing.expectEqualSlices(u8, &.{ 0x70, 0x69, 0x71, 0x72, 0x73, 0x68, 0x67, 0x66 }, tb.getBuffer(.a)[0..8]);

    try expected_b.insertSlice(allocator, 3, &.{ 0x70, 0x69 });
    try tb.insertSlice(.b, 3, &.{ 0x70, 0x69 });
    try std.testing.expectEqualSlices(u8, &.{ 0x65, 0x64, 0x65, 0x70, 0x69, 0x64, 0x63, 0x63 }, tb.getBuffer(.b)[0..8]);

    try std.testing.expectEqual(5128, tb.getBuffer(.a).len);
    try std.testing.expectEqual(expected_a.items.len, tb.getBuffer(.a).len);

    try expected_a.insertSlice(allocator, tb.getBuffer(.a).len - 3, &.{ 0x1, 0x2, 0x3, 0x4 });
    try tb.insertSlice(.a, tb.getBuffer(.a).len - 3, &.{ 0x1, 0x2, 0x3, 0x4 });
    {
        const a_buffer = tb.getBuffer(.a);
        try std.testing.expectEqualSlices(u8, &.{ 0x1, 0x2, 0x3, 0x4, 0xAA, 0xAA, 0xAA }, a_buffer[a_buffer.len - 7 ..]);
    }

    try expected_b.insertSlice(allocator, 1024, &.{ 0x1, 0x2, 0x3, 0x4 });
    try tb.insertSlice(.b, 1024, &.{ 0x1, 0x2, 0x3, 0x4 });
    {
        const b_buffer = tb.getBuffer(.b);
        try std.testing.expectEqualSlices(u8, &.{ 0x1, 0x2, 0x3, 0x4, 0xAA, 0xAA, 0xAA }, b_buffer[1024 .. 1024 + 7]);
    }

    try std.testing.expectEqualSlices(u8, expected_a.items, tb.getBuffer(.a));
    try std.testing.expectEqualSlices(u8, expected_b.items, tb.getBuffer(.b));

    const merged = try tb.toOwnedSlice(0);
    defer std.testing.allocator.free(merged);
    var expected_merged = std.array_list.Aligned(u8, null).empty;
    defer expected_merged.deinit(allocator);
    try expected_merged.appendSlice(allocator, expected_a.items);
    try expected_merged.appendSlice(allocator, expected_b.items);

    try std.testing.expectEqualSlices(u8, expected_merged.items, merged);
}

test "two buffer merges less gap" {
    const allocator = std.testing.allocator;
    var tb = TwoBuffer.init(allocator);
    defer tb.deinit();

    var expected_a = std.array_list.Aligned(u8, null).empty;
    defer expected_a.deinit(allocator);
    var expected_b = std.array_list.Aligned(u8, null).empty;
    defer expected_b.deinit(allocator);

    try tb.appendSlice(.a, &.{ 0x69, 0x68, 0x67, 0x66 });
    try expected_a.appendSlice(allocator, &.{ 0x69, 0x68, 0x67, 0x66 });

    try tb.appendSlice(.b, &.{ 0x65, 0x64, 0x63 });
    try expected_b.appendSlice(allocator, &.{ 0x65, 0x64, 0x63 });

    try tb.insertSlice(.a, 0, &.{0x70});
    try expected_a.insertSlice(allocator, 0, &.{0x70});

    try tb.appendSlice(.a, &[_]u8{0x60} ** 1024);
    try expected_a.appendSlice(allocator, &[_]u8{0x60} ** 1024);
    try tb.appendSlice(.b, &[_]u8{0x60} ** 1024);
    try expected_b.appendSlice(allocator, &[_]u8{0x60} ** 1024);

    try tb.appendSlice(.a, &[_]u8{0x60} ** 4096);
    try expected_a.appendSlice(allocator, &[_]u8{0x60} ** 4096);
    try tb.appendSlice(.b, &[_]u8{0x60} ** 4096);
    try expected_b.appendSlice(allocator, &[_]u8{0x60} ** 4096);

    const rand_resv_value = std.crypto.random.intRangeAtMost(u8, 0x1, 0xFF);

    const a_len = tb.a_len;
    const merged = try tb.toOwnedSlice(14);
    @memset(merged[a_len .. a_len + 14], rand_resv_value);

    defer std.testing.allocator.free(merged);
    var expected_merged = std.array_list.Aligned(u8, null).empty;
    defer expected_merged.deinit(allocator);
    try expected_merged.appendSlice(allocator, expected_a.items);

    const reserve_bytes = try expected_merged.addManyAsSlice(allocator, 14);
    @memset(reserve_bytes, rand_resv_value);

    try expected_merged.appendSlice(allocator, expected_b.items);

    try std.testing.expectEqualSlices(u8, expected_merged.items, merged);
}

test "two buffer merges more gap" {
    const allocator = std.testing.allocator;
    var tb = TwoBuffer.init(allocator);
    defer tb.deinit();

    var expected_a = std.array_list.Aligned(u8, null).empty;
    defer expected_a.deinit(allocator);
    var expected_b = std.array_list.Aligned(u8, null).empty;
    defer expected_b.deinit(allocator);

    try tb.appendSlice(.a, &.{ 0x69, 0x68, 0x67, 0x66 });
    try expected_a.appendSlice(allocator, &.{ 0x69, 0x68, 0x67, 0x66 });

    try tb.appendSlice(.b, &.{ 0x65, 0x64, 0x63 });
    try expected_b.appendSlice(allocator, &.{ 0x65, 0x64, 0x63 });

    try tb.insertSlice(.a, 0, &.{0x70});
    try expected_a.insertSlice(allocator, 0, &.{0x70});

    try tb.appendSlice(.a, &[_]u8{0x60} ** 1024);
    try expected_a.appendSlice(allocator, &[_]u8{0x60} ** 1024);
    try tb.appendSlice(.b, &[_]u8{0x60} ** 1024);
    try expected_b.appendSlice(allocator, &[_]u8{0x60} ** 1024);

    try tb.appendSlice(.a, &[_]u8{0x60} ** 4096);
    try expected_a.appendSlice(allocator, &[_]u8{0x60} ** 4096);
    try tb.appendSlice(.b, &[_]u8{0x60} ** 4096);
    try expected_b.appendSlice(allocator, &[_]u8{0x60} ** 4096);

    const rand_resv_value = std.crypto.random.intRangeAtMost(u8, 0x1, 0xFF);

    const a_len = tb.a_len;
    const merged = try tb.toOwnedSlice(32);
    @memset(merged[a_len .. a_len + 32], rand_resv_value);

    defer std.testing.allocator.free(merged);
    var expected_merged = std.array_list.Aligned(u8, null).empty;
    defer expected_merged.deinit(allocator);
    try expected_merged.appendSlice(allocator, expected_a.items);

    const reserve_bytes = try expected_merged.addManyAsSlice(allocator, 32);
    @memset(reserve_bytes, rand_resv_value);

    try expected_merged.appendSlice(allocator, expected_b.items);

    try std.testing.expectEqualSlices(u8, expected_merged.items, merged);
}

test "two buffer to_owned" {
    const allocator = std.testing.allocator;
    var tb = TwoBuffer.init(allocator);
    defer tb.deinit();

    var expected_a = std.array_list.Aligned(u8, null).empty;
    defer expected_a.deinit(allocator);
    var expected_b = std.array_list.Aligned(u8, null).empty;
    defer expected_b.deinit(allocator);

    try tb.appendSlice(.a, &[_]u8{0x60} ** 4096);
    try expected_a.appendSlice(allocator, &[_]u8{0x60} ** 4096);
    try tb.appendSlice(.b, &[_]u8{0x60} ** 4096);
    try expected_b.appendSlice(allocator, &[_]u8{0x60} ** 4096);

    try tb.appendSlice(.a, &.{ 0x69, 0x68, 0x67, 0x66 });
    try expected_a.appendSlice(allocator, &.{ 0x69, 0x68, 0x67, 0x66 });

    try tb.appendSlice(.b, &.{ 0x65, 0x64, 0x63 });
    try expected_b.appendSlice(allocator, &.{ 0x65, 0x64, 0x63 });

    try tb.insertSlice(.a, 0, &.{0x70});
    try expected_a.insertSlice(allocator, 0, &.{0x70});

    try tb.appendSlice(.a, &[_]u8{0x60} ** 1024);
    try expected_a.appendSlice(allocator, &[_]u8{0x60} ** 1024);
    try tb.appendSlice(.b, &[_]u8{0x60} ** 1024);
    try expected_b.appendSlice(allocator, &[_]u8{0x60} ** 1024);

    try std.testing.expectEqualSlices(u8, expected_a.items, tb.getBuffer(.a));
    try std.testing.expectEqualSlices(u8, expected_b.items, tb.getBuffer(.b));
    try std.testing.expectEqual(tb.bytes[tb.a_cap + gap_in_between ..], tb.getBuffer(.b).ptr);

    const rand_resv_value = std.crypto.random.intRangeAtMost(u8, 0x1, 0xFF);

    @memset(tb.bytes[tb.a_cap .. tb.a_cap + gap_in_between], rand_resv_value);

    const merged = try tb.toOwned(14);
    defer merged.deinit(std.testing.allocator);
    var expected_merged = std.array_list.Aligned(u8, null).empty;
    defer expected_merged.deinit(allocator);
    try expected_merged.appendSlice(allocator, expected_a.items);
    const reserve_bytes = try expected_merged.addManyAsSlice(allocator, 14);

    @memset(reserve_bytes, rand_resv_value);

    try expected_merged.appendSlice(allocator, expected_b.items);

    try std.testing.expectEqual(expected_merged.items.len, merged.items.len);

    try std.testing.expectEqualSlices(u8, expected_merged.items, merged.items);
}

test "two buffer replace range" {
    const allocator = std.testing.allocator;
    var tb = TwoBuffer.init(allocator);
    defer tb.deinit();

    var expected_a = std.array_list.Aligned(u8, null).empty;
    defer expected_a.deinit(allocator);
    var expected_b = std.array_list.Aligned(u8, null).empty;
    defer expected_b.deinit(allocator);

    try tb.appendSlice(.a, &.{ 0x69, 0x68, 0x67, 0x66 });
    try expected_a.appendSlice(allocator, &.{ 0x69, 0x68, 0x67, 0x66 });

    try tb.appendSlice(.b, &.{ 0x65, 0x64, 0x63 });
    try expected_b.appendSlice(allocator, &.{ 0x65, 0x64, 0x63 });

    try tb.insertSlice(.a, 0, &.{ 0x70, 0x71, 0x72 });
    try expected_a.insertSlice(allocator, 0, &.{ 0x70, 0x71, 0x72 });

    try tb.replaceRange(.a, 2, 4, &.{ 0xAA, 0xAA });
    try expected_a.replaceRange(allocator, 2, 4, &.{ 0xAA, 0xAA });

    try std.testing.expectEqualSlices(u8, expected_a.items, tb.getBuffer(.a));

    try tb.appendSlice(.b, &.{ 0x65, 0x64, 0x63 });
    try expected_b.appendSlice(allocator, &.{ 0x65, 0x64, 0x63 });

    try tb.replaceRange(.b, 2, 4, &.{ 0xAA, 0xAA });
    try expected_b.replaceRange(allocator, 2, 4, &.{ 0xAA, 0xAA });

    try std.testing.expectEqualSlices(u8, expected_b.items, tb.getBuffer(.b));

    try tb.replaceRange(.a, 2, 3, &.{ 0xAA, 0xAA, 0xAA, 0xAA, 0xAA });
    try expected_a.replaceRange(allocator, 2, 3, &.{ 0xAA, 0xAA, 0xAA, 0xAA, 0xAA });

    try std.testing.expectEqualSlices(u8, expected_a.items, tb.getBuffer(.a));

    try tb.appendSlice(.a, &[_]u8{0x60} ** 4096);
    try expected_a.appendSlice(allocator, &[_]u8{0x60} ** 4096);
    try tb.appendSlice(.b, &[_]u8{0x60} ** 4096);
    try expected_b.appendSlice(allocator, &[_]u8{0x60} ** 4096);

    const rand_resv_value = std.crypto.random.intRangeAtMost(u8, 0x1, 0xFF);

    @memset(tb.bytes[tb.a_cap .. tb.a_cap + gap_in_between], rand_resv_value);

    const merged = try tb.toOwned(14);
    defer merged.deinit(std.testing.allocator);
    var expected_merged = std.array_list.Aligned(u8, null).empty;
    defer expected_merged.deinit(allocator);
    try expected_merged.appendSlice(allocator, expected_a.items);
    const reserve_bytes = try expected_merged.addManyAsSlice(allocator, 14);

    @memset(reserve_bytes, rand_resv_value);

    try expected_merged.appendSlice(allocator, expected_b.items);

    try std.testing.expectEqual(expected_merged.items.len, merged.items.len);

    try std.testing.expectEqualSlices(u8, expected_merged.items, merged.items);
}

test "two buffer replace with empty range" {
    const allocator = std.testing.allocator;
    var tb = TwoBuffer.init(allocator);
    defer tb.deinit();

    var expected_a = std.array_list.Aligned(u8, null).empty;
    defer expected_a.deinit(allocator);
    var expected_b = std.array_list.Aligned(u8, null).empty;
    defer expected_b.deinit(allocator);

    try tb.appendSlice(.a, &.{ 0x69, 0x68, 0x67, 0x66 });
    try expected_a.appendSlice(allocator, &.{ 0x69, 0x68, 0x67, 0x66 });

    try tb.appendSlice(.b, &.{ 0x65, 0x64, 0x63 });
    try expected_b.appendSlice(allocator, &.{ 0x65, 0x64, 0x63 });

    try tb.insertSlice(.a, 0, &.{ 0x70, 0x71, 0x72 });
    try expected_a.insertSlice(allocator, 0, &.{ 0x70, 0x71, 0x72 });

    try tb.appendSlice(.a, &.{ 0x65, 0x64, 0x63, 0x62 });
    try expected_a.appendSlice(allocator, &.{ 0x65, 0x64, 0x63, 0x62 });

    try tb.replaceRange(.a, 2, 4, &.{});
    try expected_a.replaceRange(allocator, 2, 4, &.{});

    try std.testing.expectEqual(7, tb.len(.a));
    try std.testing.expectEqualSlices(u8, &.{ 0x70, 0x71, 0x66, 0x65, 0x64, 0x63, 0x62 }, tb.getBuffer(.a));
    try std.testing.expectEqualSlices(u8, expected_a.items, tb.getBuffer(.a));
}

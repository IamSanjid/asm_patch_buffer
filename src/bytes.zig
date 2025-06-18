const std = @import("std");

const assert = std.debug.assert;

fn RuntimeIntType(comptime value: comptime_int) type {
    const int_types = if (value < 0) [_]type{ i8, i16, i32 } else [_]type{ u8, u16, u32 };
    for (int_types) |IntType| {
        if (value >= std.math.minInt(IntType) and value <= std.math.maxInt(IntType)) {
            return IntType;
        }
    }
    @compileError("Int value too big/small, not supported yet");
}

fn getTupleComptimeItemsLenInBytes(comptime T: type) comptime_int {
    const info = @typeInfo(T);
    assert(info == .@"struct" and info.@"struct".is_tuple);
    const info_struct = info.@"struct";

    var len = 0;
    for (info_struct.fields) |field| {
        if (field.is_comptime) {
            if (field.type == comptime_int) {
                const value = field.defaultValue() orelse continue;
                len += @sizeOf(RuntimeIntType(value));
            } else if (field.type == comptime_float) {
                @compileError("Please use '@as(f32/f64/.., ...)' for floating point values, cannot infer the size.");
            } else {
                len += @sizeOf(field.type);
            }
            // const field_info = @typeInfo(field.type);
            // if (field.type == comptime_int) {
            //     const value = field.defaultValue() orelse continue;
            //     len += @sizeOf(RuntimeIntType(value));
            // } else if (field_info == .int) {
            //     len += @sizeOf(field.type);
            // } else {
            //     @compileError("Comptime field type must be an int");
            // }
        }
    }

    return len;
}

fn getTupleItemsLenInBytes(comptime T: type) comptime_int {
    const info = @typeInfo(T);

    if (info != .@"struct" or !info.@"struct".is_tuple) {
        @compileError("Need tuple struct type.");
    }

    const info_struct = info.@"struct";

    var len = getTupleComptimeItemsLenInBytes(T);
    for (info_struct.fields) |field| {
        if (!field.is_comptime) {
            len += @sizeOf(field.type);
        }
    }

    return len;
}

fn comptimeIntToBytes(comptime T: type, comptime value: comptime_int) [@sizeOf(T)]u8 {
    return std.mem.toBytes(@as(T, value));
}

fn U8SliceOrArrayType(comptime T: type) ?type {
    if (T == []const u8) {
        return T;
    }
    const field_type_info = @typeInfo(T);
    switch (field_type_info) {
        .array => |array| {
            if (array.child == u8) {
                return T;
            }
        },
        .pointer => |pointer| {
            if (pointer.child == u8) {
                return T;
            }

            if (pointer.sentinel()) |sentinel| {
                if (sentinel == 0 and pointer.child == u8) {
                    return T;
                }
            }

            const child_info = @typeInfo(pointer.child);
            if (child_info == .array and child_info.array.child == u8) {
                return T;
            }
        },
        else => {},
    }

    return null;
}

// inline fn getU8Slice(comptime T: type, v: T) []const u8 {
//     if (T == []const u8) {
//         return v;
//     }
//     const field_type_info = @typeInfo(T);
//     switch (field_type_info) {
//         .array => |array| {
//             if (array.child == u8) {
//                 const value_as_bytes: []const u8 = &v;
//                 return value_as_bytes;
//             }
//         },
//         .pointer => |pointer| {
//             if (pointer.child == u8 and pointer.size == .slice) {
//                 const value_as_bytes: []const u8 = v;
//                 return value_as_bytes;
//             }

//             if (pointer.sentinel()) |sentinel| {
//                 if (sentinel == 0 and pointer.child == u8) {
//                     return std.mem.span(v);
//                 }
//             }

//             const child_info = @typeInfo(pointer.child);
//             if (child_info == .array and child_info.array.child == u8) {
//                 const value_as_bytes: []const u8 = v;
//                 return value_as_bytes;
//             }
//         },
//         else => {},
//     }

//     @compileError("Only expected []const u8(coercible)");
// }

pub fn BytesType(comptime T: type) type {
    if (U8SliceOrArrayType(T)) |RetT| return RetT;
    return [getTupleItemsLenInBytes(T)]u8;
}

pub fn bytes(tuple: anytype) BytesType(@TypeOf(tuple)) {
    const TupleType = @TypeOf(tuple);
    if (U8SliceOrArrayType(TupleType)) |_| return tuple;

    const info = @typeInfo(TupleType);

    if (info != .@"struct" or !info.@"struct".is_tuple) {
        @compileError("Need tuple struct type.");
    }

    var result_bytes: [getTupleItemsLenInBytes(TupleType)]u8 = undefined;

    const info_struct = info.@"struct";
    var index: usize = 0;
    inline for (info_struct.fields, 0..) |field, i| {
        if (field.is_comptime) {
            if (field.type != comptime_int) {
                const dp: *const field.type = @ptrCast(@alignCast(field.default_value_ptr orelse unreachable));
                @memcpy(result_bytes[index .. index + @sizeOf(field.type)], std.mem.asBytes(dp));
                index += @sizeOf(field.type);
            } else {
                const value = field.defaultValue() orelse unreachable;
                const RtType = RuntimeIntType(value);
                @memcpy(result_bytes[index .. index + @sizeOf(RtType)], comptimeIntToBytes(RtType, value)[0..]);
                index += @sizeOf(RtType);
            }
            // const field_info = @typeInfo(field.type);
            // if (field_info == .int) {
            //     const value = field.defaultValue() orelse unreachable;
            //     @memcpy(result_bytes[index .. index + @sizeOf(field.type)], std.mem.asBytes(&value));
            //     index += @sizeOf(field.type);
            // } else {
            //     if (field.type != comptime_int) @compileError("For comptime value, only comptime_int types are supported");
            //     const value = field.defaultValue() orelse unreachable;
            //     inline for (comptimeIntToBytes(RuntimeIntType(value), value)) |byte| {
            //         result_bytes[index] = byte;
            //         index += 1;
            //     }
            // }
        } else {
            @memcpy(result_bytes[index .. index + @sizeOf(field.type)], std.mem.asBytes(&tuple[i]));
            index += @sizeOf(field.type);
        }
    }

    return result_bytes;
}

test "bytes" {
    const target: usize = try std.fmt.parseInt(usize, "0x1234", 0);
    const target2: u8 = try std.fmt.parseInt(u8, "0x10", 0);
    const b = bytes(.{
        0x50,
        0x60,
        0x70,
        target,
        target2,
        -1,
    });

    try std.testing.expectEqualSlices(u8, &.{ 0x50, 0x60, 0x70 }, b[0..3]);
    try std.testing.expectEqualSlices(u8, std.mem.asBytes(&target), b[3 .. 3 + @sizeOf(usize)]);
    try std.testing.expectEqualSlices(u8, std.mem.asBytes(&target2), b[3 + @sizeOf(usize) .. 3 + @sizeOf(usize) + @sizeOf(u8)]);
    try std.testing.expectEqualSlices(u8, &.{255}, b[3 + @sizeOf(usize) + @sizeOf(u8) ..]);
}

test "bytes coerce itself" {
    const target: usize = try std.fmt.parseInt(usize, "0x1234", 0);
    const target2: u8 = try std.fmt.parseInt(u8, "0x10", 0);
    const b_orig = bytes(.{
        0x50,
        0x60,
        0x70,
        target,
        target2,
        -1,
    });

    const b = bytes(b_orig);
    try std.testing.expectEqualSlices(u8, &.{ 0x50, 0x60, 0x70 }, b[0..3]);
    try std.testing.expectEqualSlices(u8, std.mem.asBytes(&target), b[3 .. 3 + @sizeOf(usize)]);
    try std.testing.expectEqualSlices(u8, std.mem.asBytes(&target2), b[3 + @sizeOf(usize) .. 3 + @sizeOf(usize) + @sizeOf(u8)]);
    try std.testing.expectEqualSlices(u8, &.{255}, b[3 + @sizeOf(usize) + @sizeOf(u8) ..]);
}

test "bytes coerce other u8 slices types" {
    {
        const sentinel: [:0]const u8 = "TEST!";
        const b = bytes(sentinel);
        try std.testing.expectEqualStrings(sentinel, b);
    }
    {
        const sentinel: [:0]const u8 = "TEST!";
        const b = bytes(sentinel.ptr);
        try std.testing.expectEqual(@TypeOf(b), @TypeOf(sentinel.ptr));
        try std.testing.expectEqualStrings(sentinel, std.mem.span(b));
    }
    {
        const normal: []const u8 = "TEST!";
        const b = bytes(normal);
        try std.testing.expectEqualStrings(normal, b);
    }
    {
        const normal: []const u8 = "TEST!";
        const b = bytes(normal.ptr);
        try std.testing.expectEqual(@TypeOf(b), @TypeOf(normal.ptr));
        try std.testing.expectEqualStrings(normal, b[0..normal.len]);
    }
}

test "struct bytes" {
    const DummyStruct = struct {
        a: u8 = 0x20,
        b: u16 = 0x110,
        c: u32 = 0x2222,
        d: usize = 0x6969,
    };
    const ds = DummyStruct{};
    const target: usize = try std.fmt.parseInt(usize, "0x1234", 0);
    const target2: u8 = try std.fmt.parseInt(u8, "0x10", 0);
    const b = bytes(.{
        0x50,
        0x60,
        0x70,
        target,
        target2,
        ds,
    });

    try std.testing.expectEqualSlices(u8, &.{ 0x50, 0x60, 0x70 }, b[0..3]);
    try std.testing.expectEqualSlices(u8, std.mem.asBytes(&target), b[3 .. 3 + @sizeOf(usize)]);
    try std.testing.expectEqualSlices(u8, std.mem.asBytes(&target2), b[3 + @sizeOf(usize) .. 3 + @sizeOf(usize) + @sizeOf(u8)]);
    try std.testing.expectEqualSlices(u8, std.mem.asBytes(&ds), b[3 + @sizeOf(usize) + @sizeOf(u8) ..]);
}

pub fn patternMatchBytes(tuple: anytype, input: []const u8) bool {
    const TupleType = @TypeOf(tuple);

    const info = @typeInfo(TupleType);

    if (info != .@"struct" or !info.@"struct".is_tuple) {
        @compileError("Need tuple struct type.");
    }

    const info_struct = info.@"struct";
    var index: usize = 0;
    inline for (info_struct.fields, 0..) |field, i| {
        if (field.is_comptime) {
            if (field.type != comptime_int) {
                const dp: *const field.type = @ptrCast(@alignCast(field.default_value_ptr orelse unreachable));

                if (index + @sizeOf(field.type) > input.len) return false;

                if (!std.mem.eql(u8, input[index .. index + @sizeOf(field.type)], std.mem.asBytes(dp))) return false;
                index += @sizeOf(field.type);
            } else {
                const value = field.defaultValue() orelse unreachable;
                const RtType = RuntimeIntType(value);

                if (index + @sizeOf(RtType) > input.len) return false;

                if (!std.mem.eql(u8, input[index .. index + @sizeOf(RtType)], comptimeIntToBytes(RtType, value)[0..])) return false;
                index += @sizeOf(RtType);
            }
        } else {
            const field_type_info = @typeInfo(field.type);
            if (field_type_info == .pointer) {
                if (field_type_info.pointer.size != .one) @compileError("Must receive single item pointer");
                if (field_type_info.pointer.is_const) @compileError("pointer to const int, cannot write...");

                if (@typeInfo(field_type_info.pointer.child) == .int) {
                    const child_type_size = @sizeOf(field_type_info.pointer.child);

                    if (index + child_type_size > input.len) return false;

                    @setRuntimeSafety(false);
                    tuple[i].* = @as(field.type, @ptrFromInt(@intFromPtr(input[index..].ptr))).*;
                    index += child_type_size;
                } else @compileError("Only int type pointer extraction supported for now..");
            } else {
                if (index + @sizeOf(field.type) > input.len) return false;

                if (!std.mem.eql(u8, input[index .. index + @sizeOf(field.type)], std.mem.asBytes(&tuple[i]))) return false;
                index += @sizeOf(field.type);
            }
        }
    }

    return true;
}

test "patternMatchBytes basic" {
    const target: usize = try std.fmt.parseInt(usize, "0x1234", 0);
    const target2: u8 = try std.fmt.parseInt(u8, "10", 0);

    const matched = patternMatchBytes(
        .{ 0x68, 0x64, target, target2, 0x70, 0x10 },
        &bytes(.{ 0x68, 0x64, target, target2, 0x70, 0x10 }),
    );
    try std.testing.expect(matched);
}

test "patternMatchBytes extract" {
    const target: usize = try std.fmt.parseInt(usize, "0x1234", 0);
    const target2: u8 = try std.fmt.parseInt(u8, "10", 0);

    var extract1: usize = undefined;
    var extract2: u8 = undefined;

    const matched = patternMatchBytes(
        .{ 0x68, 0x64, &extract1, &extract2 },
        &bytes(.{ 0x68, 0x64, target, target2, 0x70, 0x10 }),
    );
    try std.testing.expect(matched);
    try std.testing.expectEqual(extract1, target);
    try std.testing.expectEqual(extract2, target2);
}

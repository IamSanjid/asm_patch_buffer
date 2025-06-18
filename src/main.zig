const std = @import("std");

const assert = std.debug.assert;

const pb = @import("asm_patch_buffer");
const bytes = pb.bytes;

pub const Reference = struct {
    value: []const u8,
    size: usize,
};

const reference = pb.reference;
const useReference = pb.useReference;
const mark = pb.mark;

const Target = struct { usize, usize };

fn replacing(target: Target, tuple: anytype) void {
    const TupleType = @TypeOf(tuple);
    const info = @typeInfo(TupleType);

    if (info != .@"struct" or !info.@"struct".is_tuple) {
        @compileError("Need tuple struct type.");
    }

    std.debug.print("Replacing! {any}\n", .{target});

    const struct_info = info.@"struct";
    inline for (struct_info.fields) |field| {
        const value = @field(tuple, field.name);
        //@compileLog(@typeName(field.type));
        // if (field.type == Reference) {
        //     std.debug.print("  Reference found!: {any}({})\n", .{ value, value.size });
        // }
        // if (field.type == UseReference) {
        //     std.debug.print("  UseReference found!: {any}\n", .{value});
        // }
        std.debug.print("  {any}\n", .{value});
    }
}

pub fn main() !void {
    const target: usize = try std.fmt.parseInt(usize, "0x1234", 0);
    const target2: u8 = try std.fmt.parseInt(u8, "10", 0);
    const b = bytes(.{
        50,
        60,
        70,
        target,
        target2,
        -1,
    });
    std.debug.print("b({}): {any}\n", .{ b.len, b });

    var patch_buffer = pb.AsmPatchBuffer.init(std.heap.c_allocator, &b);
    defer patch_buffer.deinit();

    replacing(.{ 1, 1 }, .{
        bytes(.{ 0x50, 0x60, 0x70 }),
        reference(@sizeOf(u32), &bytes(.{target})),
        bytes(.{ 0x50, 0x60, 0x70 }),
        useReference(.last),
        reference(@sizeOf(usize), &bytes(.{target2})),
        bytes(.{ 0x80, 0xF0, 0xC0 }),
        useReference(0),
        bytes(.{ 0x80, 0xF0, 0xC0 }),
    });

    // try patch_buffer.replacing(10, .{
    //     bytes(.{ 0x50, 0x60, 0x70 }),
    //     reference(@sizeOf(u32), .{target}),
    //     bytes(.{ 0x50, 0x60, 0x70 }),
    //     useReference(.last),
    //     reference(@sizeOf(usize), .{target2}),
    //     bytes(.{ 0x80, 0xF0, 0xC0 }),
    //     useReference(0),
    //     bytes(.{ 0x80, 0xF0, 0xC0 }),
    // });

    try patch_buffer.replace(10, .{
        bytes(.{ 0x50, 0x60, 0x70 }),
        reference(@sizeOf(u32), .{target}),
        bytes(.{ 0x50, 0x60, 0x70 }),
        useReference(.last),
        reference(@sizeOf(usize), .{target2}),
        bytes(.{ 0x80, 0xF0, 0xC0 }),
        useReference(0),
        bytes(.{ 0x80, 0xF0, 0xC0 }),
    });
}

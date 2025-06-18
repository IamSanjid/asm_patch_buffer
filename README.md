# asm_patch_buffer

Just some (ab)uses of zig's comptime capabilities.

# Exampls

```zig
const apb = @import("asm_patch_buffer");

const bytes = apb.bytes;
const patternMatchBytes = apb.patternMatchBytes;
const reference = apb.reference;
const useReference = apb.useReference;
const reusableReference = apb.reusableReference;
const reusableReferenceOrCreate = apb.reusableReferenceOrCreate;
const mark = apb.mark;

const AsmPatchBuffer = apb.AsmPatchBuffer;

// ================= AsmPatchBuffer =================
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
// Check the source to learn more about `AsmPatchBuffer`'s usage. I will put the way I use in one of my projects later..
try std.testing.expectEqual(16, committed.reserved_offset);
try std.testing.expectEqual(16 + 14, committed.refrences.items[0].calculateValueOffset());
try std.testing.expectEqual(16 + 14 + @sizeOf(usize), committed.refrences.items[1].calculateValueOffset());
try std.testing.expectEqualSlices(u8, &.{ 0xC, 0xD }, committed.buffer.items[committed.refrences.items[1].calculateValueOffset()..]);
try std.testing.expectEqual(orig.len + 14 + 2 + @sizeOf(usize), committed.buffer.items.len);
try std.testing.expectEqual(10 + 14, committed.refrences.items[0].value_offset);

// ================= bytes ===================
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
// `b` will contain the the bytes of `target` and `target2` in the same order they're placed.

// ================= patternMatchBytes ===================
const target: usize = try std.fmt.parseInt(usize, "0x1234", 0);
const target2: u8 = try std.fmt.parseInt(u8, "10", 0);

var extract1: usize = undefined;
var extract2: u8 = undefined;

const matched = patternMatchBytes(
    .{ 0x68, 0x64, &extract1, &extract2 },
    &bytes(.{ 0x68, 0x64, target, target2, 0x70, 0x10 }),
);
// will work as you might be guessing, it will first try to match the contant values if any `int`
// single item pointers are given it will just read given type's size amount of
// bytes(if not avaialble returns false) and store to those pointer.

// try std.testing.expect(matched);
// try std.testing.expectEqual(extract1, target);
// try std.testing.expectEqual(extract2, target2);
```

# Usage?
Typical `zig fetch --save git+<url>`
```zig
const asm_patch_buffer_dep = b.dependency("asm_patch_buffer", .{
    .target = b.standardTargetOptions(.{}),
    .optimize = b.standardOptimizeOption(.{}),
});
const asm_patch_buffer = asm_patch_buffer_dep.module("asm_patch_buffer");
// import `asm_patch_buffer` using `addImport` function
```
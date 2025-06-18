test {
    _ = @import("bytes.zig");
    _ = @import("asm_patch_buffer.zig");
    _ = @import("TwoBuffer.zig");
    @import("std").testing.refAllDecls(@This());
}

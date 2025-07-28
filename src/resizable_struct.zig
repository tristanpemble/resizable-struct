//! Structs with runtime-sized array fields.
//!
//! This module provides `ResizableStruct` for creating heap-allocated types that can be sized at runtime
//! and `ResizableArray` for marking the fields on that struct that are variable-length arrays.

pub const Error = error{
    OutOfMemory,
    InvalidLength,
};

/// This type is zero sized and has no methods. It exists as an API for `ResizableStruct`,
/// indicating which fields are runtime sized arrays of elements.
pub fn ResizableArray(comptime T: type) type {
    return struct {
        pub const Element = T;
        // This forces alignment to match the element type, which ResizableStruct uses to ensure proper alignment.
        _: void align(@alignOf(T)) = {},
    };
}

fn isResizableArray(comptime T: type) bool {
    return @typeInfo(T) == .@"struct" and @hasDecl(T, "Element") and T == ResizableArray(T.Element);
}

/// A heap allocated type that can be sized at runtime to contain any number of `ResizableArray`s.
///
/// Internally, it is represented as a pointer and a set of lengths for each `ResizableArray` field.
pub fn ResizableStruct(comptime Layout: type) type {
    comptime {
        if (@typeInfo(Layout).@"struct".layout == .@"packed") {
            @compileError("Packed structs have a fixed size and are fundamentally incompatible with the idea of a resizable struct.");
        }
    }

    return struct {
        const Self = @This();

        /// Struct field information; sorts fields by alignment when layout is auto.
        const field_info = blk: {
            const info = @typeInfo(Layout).@"struct";
            var fields: [info.fields.len]StructField = undefined;
            for (info.fields, 0..) |field, i| {
                fields[i] = field;
            }
            if (info.layout == .auto) {
                const Sort = struct {
                    fn lessThan(_: void, lhs: StructField, rhs: StructField) bool {
                        return lhs.alignment > rhs.alignment;
                    }
                };
                mem.sort(StructField, &fields, {}, Sort.lessThan);
            }
            break :blk fields;
        };

        /// A comptime generated struct type containing `usize` length fields for each `ResizableArray` field of `Layout`.
        pub const Lengths = blk: {
            var fields: [field_info.len]StructField = undefined;
            var i: usize = 0;
            for (field_info) |field| {
                if (isResizableArray(field.type)) {
                    fields[i] = .{
                        .name = field.name,
                        .type = usize,
                        .default_value_ptr = @ptrCast(&@as(usize, 0)),
                        .is_comptime = false,
                        .alignment = @alignOf(usize),
                    };
                    i += 1;
                }
            }
            break :blk @Type(.{
                .@"struct" = .{
                    .layout = .auto,
                    .fields = fields[0..i],
                    .decls = &.{},
                    .is_tuple = false,
                },
            });
        };

        /// The pointer to the struct's data.
        ptr: [*]align(@alignOf(Layout)) u8,

        /// The length of each `ResizableArray` field.
        lens: Lengths,

        /// Initializes a new instance of the struct with the given lengths of its `ResizableArray` fields.
        pub fn init(allocator: Allocator, lens: Lengths) Error!Self {
            const size = calcSize(lens);
            const bytes = try allocator.alignedAlloc(u8, @alignOf(Layout), size);

            return Self{ .ptr = bytes.ptr, .lens = lens };
        }

        /// Deinitializes the struct, freeing its memory.
        pub fn deinit(self: *Self, allocator: Allocator) void {
            allocator.free(self.ptr[0..calcSize(self.lens)]);
            self.* = undefined;
        }

        /// Takes ownership of the passed in byte slice.
        pub fn fromOwnedBytes(bytes: []align(@alignOf(Layout)) u8, lens: Lengths) Error!Self {
            if (bytes.len != calcSize(lens)) return error.InvalidLength;
            return .{
                .ptr = bytes.ptr,
                .lens = lens,
            };
        }

        /// Returns a slice of the underlying bytes.
        pub fn asBytes(self: Self) []u8 {
            return self.ptr[0..calcSize(self.lens)];
        }

        /// Resizes the struct. Invalidates element pointers if relocation is needed.
        pub fn resize(self: *Self, allocator: Allocator, new_lens: Lengths) Error!void {
            if (std.meta.eql(self.lens, new_lens)) return;

            // For now, we always reallocate when resizing. We could try to support resizing
            // in place, but the added complexity seems unlikely to be worth it for most use cases.
            const new_size = calcSize(new_lens);
            const new_bytes = try allocator.alignedAlloc(u8, @alignOf(Layout), new_size);

            inline for (field_info) |field| {
                const old_field_offset = offsetOf(field.name, self.lens);
                const old_field_size = sizeOf(field.name, self.lens);
                const old_field_bytes = self.ptr[old_field_offset .. old_field_offset + old_field_size];

                const new_field_offset = offsetOf(field.name, new_lens);
                const new_field_size = sizeOf(field.name, new_lens);
                const new_field_bytes = new_bytes[new_field_offset .. new_field_offset + new_field_size];

                const copy_size = @min(old_field_size, new_field_size);
                @memcpy(new_field_bytes[0..copy_size], old_field_bytes[0..copy_size]);
            }

            allocator.free(self.ptr[0..calcSize(self.lens)]);
            self.ptr = new_bytes.ptr;
            self.lens = new_lens;
        }

        /// Returns a pointer to the given field. If the field is a `ResizableArray`, returns a slice of elements.
        pub fn get(self: Self, comptime field: FieldEnum(Layout)) blk: {
            const Field = @FieldType(Layout, @tagName(field));
            break :blk if (isResizableArray(Field)) []Field.Element else *Field;
        } {
            const offset = offsetOf(@tagName(field), self.lens);
            const size = sizeOf(@tagName(field), self.lens);
            const bytes = self.ptr[offset..][0..size];

            return @ptrCast(@alignCast(bytes));
        }

        /// Returns the byte offset of the given field.
        fn offsetOf(comptime field_name: []const u8, lens: Lengths) usize {
            var offset: usize = 0;
            inline for (field_info) |f| {
                offset = std.mem.alignForward(usize, offset, f.alignment);
                if (comptime std.mem.eql(u8, f.name, field_name)) {
                    return offset;
                } else {
                    offset += sizeOf(f.name, lens);
                }
            }
            unreachable;
        }

        /// Returns the byte size of the given field, calculating the size of `ResizableArray` fields using their length.
        fn sizeOf(comptime field_name: []const u8, lens: Lengths) usize {
            const Field = @FieldType(Layout, field_name);
            if (comptime isResizableArray(Field)) {
                return @sizeOf(Field.Element) * @field(lens, field_name);
            } else {
                return @sizeOf(Field);
            }
        }

        /// Returns the byte alignment of the given field.
        fn alignOf(comptime field_name: []const u8) usize {
            return std.meta.fieldInfo(Layout, @field(FieldEnum(Layout), field_name)).alignment;
        }

        /// Calculate the byte size of this struct given the lengths of its `ResizableArray` fields.
        fn calcSize(lens: Lengths) usize {
            const tail_field = field_info[field_info.len - 1].name;
            const tail_size = sizeOf(tail_field, lens);
            const tail_offset = offsetOf(tail_field, lens);

            return std.mem.alignForward(usize, tail_offset + tail_size, @alignOf(Layout));
        }
    };
}

test "ResizableArray alignment" {
    try testing.expectEqual(16, @alignOf(ResizableArray(u128)));
    try testing.expectEqual(8, @alignOf(ResizableArray(u64)));
    try testing.expectEqual(4, @alignOf(ResizableArray(u32)));
    try testing.expectEqual(2, @alignOf(ResizableArray(u16)));
    try testing.expectEqual(1, @alignOf(ResizableArray(u8)));
}

test "ResizableArray alignment as a field" {
    const fields = @typeInfo(struct {
        a: ResizableArray(u128),
        b: ResizableArray(u64),
        c: ResizableArray(u32),
        d: ResizableArray(u16),
        u: ResizableArray(u8),
    }).@"struct".fields;

    try testing.expectEqual(16, fields[0].alignment);
    try testing.expectEqual(8, fields[1].alignment);
    try testing.expectEqual(4, fields[2].alignment);
    try testing.expectEqual(2, fields[3].alignment);
    try testing.expectEqual(1, fields[4].alignment);
}

test "calcSize is multiple of alignment" {
    const Layout = struct {
        head: u128 align(8),
        tail: ResizableArray(u8),
    };
    const MyType = ResizableStruct(Layout);

    try testing.expectEqual(@sizeOf(u128), MyType.calcSize(.{
        .tail = 0,
    }));

    inline for (1..@alignOf(Layout) + 1) |i| {
        try testing.expectEqual(@sizeOf(u128) + @alignOf(Layout), MyType.calcSize(.{
            .tail = i,
        }));
    }

    try testing.expectEqual(@sizeOf(u128) + 2 * @alignOf(Layout), MyType.calcSize(.{
        .tail = @alignOf(Layout) + 1,
    }));
}

test "allocated" {
    const Head = struct {
        head_val: u32,
    };
    const Middle = struct {
        middle_val: u32,
    };
    const Tail = struct {
        tail_val: u32,
    };
    const MyType = ResizableStruct(struct {
        head: Head,
        first: ResizableArray(u32),
        middle: Middle,
        second: ResizableArray(u8),
        tail: Tail,
    });

    var my_type = try MyType.init(testing.allocator, .{
        .first = 2,
        .second = 4,
    });
    defer my_type.deinit(testing.allocator);

    const head = my_type.get(.head);
    head.* = Head{ .head_val = 0xAA };
    var first = my_type.get(.first);
    first[0] = 0xC0FFEE;
    first[1] = 0xBEEF;
    const middle = my_type.get(.middle);
    middle.* = Middle{ .middle_val = 0xBB };
    var second = my_type.get(.second);
    second[0] = 0xC0;
    second[1] = 0xDE;
    second[2] = 0xD0;
    second[3] = 0x0D;
    const tail = my_type.get(.tail);
    tail.* = Tail{ .tail_val = 0xCC };

    try testing.expectEqualDeep(&Head{ .head_val = 0xAA }, my_type.get(.head));
    try testing.expectEqual(2, my_type.get(.first).len);
    try testing.expectEqualSlices(u32, &.{ 0xC0FFEE, 0xBEEF }, my_type.get(.first));
    try testing.expectEqualDeep(&Middle{ .middle_val = 0xBB }, my_type.get(.middle));
    try testing.expectEqual(4, my_type.get(.second).len);
    try testing.expectEqualSlices(u8, &.{ 0xC0, 0xDE, 0xD0, 0x0D }, my_type.get(.second));
    try testing.expectEqualDeep(&Tail{ .tail_val = 0xCC }, my_type.get(.tail));

    try my_type.resize(testing.allocator, .{
        .first = 3,
        .second = 5,
    });

    first = my_type.get(.first);
    first[2] = 0xF00B42;
    second = my_type.get(.second);
    second[4] = 0x42;

    try testing.expectEqualDeep(&Head{ .head_val = 0xAA }, my_type.get(.head));
    try testing.expectEqual(3, my_type.get(.first).len);
    try testing.expectEqualSlices(u32, &.{ 0xC0FFEE, 0xBEEF, 0xF00B42 }, my_type.get(.first));
    try testing.expectEqualDeep(&Middle{ .middle_val = 0xBB }, my_type.get(.middle));
    try testing.expectEqual(5, my_type.get(.second).len);
    try testing.expectEqualSlices(u8, &.{ 0xC0, 0xDE, 0xD0, 0x0D, 0x42 }, my_type.get(.second));
    try testing.expectEqualDeep(&Tail{ .tail_val = 0xCC }, my_type.get(.tail));
}

test "extern struct" {
    const Bytes = ResizableStruct(extern struct {
        a: u8,
        b: u8 align(4),
        c: ResizableArray(u8),
        d: ResizableArray(u128),
    });

    var val = try Bytes.init(testing.allocator, .{
        .c = 21,
        .d = 1,
    });
    defer val.deinit(testing.allocator);

    // Ensure alignment
    try testing.expectEqual(1, Bytes.sizeOf("a", val.lens));
    try testing.expectEqual(0, Bytes.offsetOf("a", val.lens));
    try testing.expectEqual(1, Bytes.sizeOf("b", val.lens));
    try testing.expectEqual(4, Bytes.offsetOf("b", val.lens));
    try testing.expectEqual(21, Bytes.sizeOf("c", val.lens));
    try testing.expectEqual(5, Bytes.offsetOf("c", val.lens));
    try testing.expectEqual(16, Bytes.sizeOf("d", val.lens));
    try testing.expectEqual(32, Bytes.offsetOf("d", val.lens));

    // Test field access
    const c = val.get(.c);
    c[0] = 0xC0;
    c[1] = 0xFF;
    c[2] = 0xEE;
    try testing.expectEqualSlices(u8, &.{ 0xC0, 0xFF, 0xEE }, val.get(.c)[0..3]);

    const d = val.get(.d);
    d[0] = 0xBEEF;
    try testing.expectEqualSlices(u128, &.{0xBEEF}, val.get(.d)[0..1]);

    try val.resize(testing.allocator, .{
        .c = 512,
        .d = 256,
    });
    try testing.expectEqual(512, val.get(.c).len);
    try testing.expectEqual(256, val.get(.d).len);
    try testing.expectEqualSlices(u8, &.{ 0xC0, 0xFF, 0xEE }, val.get(.c)[0..3]);
    try testing.expectEqualSlices(u128, &.{0xBEEF}, val.get(.d)[0..1]);
}

test "fromOwnedBytes" {
    var packet = [_]u16{
        4,
        0xD00D,
        0xCAFE,
        0xBEEF,
        0xDEAD,
    };
    const Bytes = ResizableStruct(struct {
        len: u16,
        data: ResizableArray(u16),
    });

    const bytes = try Bytes.fromOwnedBytes(@ptrCast(packet[0..]), .{ .data = 4 });
    try testing.expectEqualSlices(u16, packet[1..], bytes.get(.data));
}

test "asBytes" {
    var packet = [_]u16{
        4,
        0xD00D,
        0xCAFE,
        0xBEEF,
        0xDEAD,
    };

    const Bytes = ResizableStruct(struct {
        len: u16,
        data: ResizableArray(u16),
    });

    const bytes = Bytes{
        .ptr = std.mem.asBytes(packet[0..]),
        .lens = .{
            .data = 4,
        },
    };

    try testing.expectEqualSlices(u8, std.mem.asBytes(packet[0..]), bytes.asBytes());
}

const std = @import("std");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;
const FieldEnum = std.meta.FieldEnum;
const mem = std.mem;
const Struct = std.builtin.Type.Struct;
const StructField = std.builtin.Type.StructField;
const testing = std.testing;

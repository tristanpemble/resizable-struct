//! A slice-like data structure for working with structs that hold runtime sized array fields.
//!
//! This module provides a `StructuredSlice`, which acts as a multi-field slice, and `FlexibleArray`
//! for marking the fields in the `StructuredSlice` layout that are sized at runtime.

pub const Error = error{
    OutOfMemory,
    InvalidLength,
};

/// This type is zero sized and has no methods. It exists as an API for `StructuredSlice`,
/// indicating which fields are runtime sized arrays of elements.
pub fn FlexibleArray(comptime T: type) type {
    return struct {
        pub const Element = T;
        // This forces alignment to match the element type, which StructuredSlice uses to ensure proper alignment.
        _: void align(@alignOf(T)) = {},
    };
}

fn isFlexibleArray(comptime T: type) bool {
    return @typeInfo(T) == .@"struct" and @hasDecl(T, "Element") and T == FlexibleArray(T.Element);
}

/// A slice-like type for working with structs that can hold runtime sized `FlexibleArray`s.
///
/// Internally, it is represented as a pointer and a set of lengths for each `FlexibleArray` field.
pub fn StructuredSlice(comptime Layout: type) type {
    comptime {
        if (@typeInfo(Layout).@"struct".layout == .@"packed") {
            @compileError("Packed structs have a fixed size and cannot be used with a StructuredSlice.");
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

        /// A comptime generated struct type containing `usize` length fields for each `FlexibleArray` field of `Layout`.
        pub const Lengths = blk: {
            var fields: [field_info.len]StructField = undefined;
            var i: usize = 0;
            for (field_info) |field| {
                if (isFlexibleArray(field.type)) {
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

        /// The length of each `FlexibleArray` field.
        lens: Lengths,

        /// Initializes a new instance of the struct with the given lengths of its `FlexibleArray` fields.
        pub fn init(allocator: Allocator, lens: Lengths) Error!Self {
            const size = calcSize(lens);
            const bytes = try allocator.alignedAlloc(u8, @alignOf(Layout), size);

            return Self{ .ptr = bytes.ptr, .lens = lens };
        }

        /// Deinitializes the struct, freeing its memory.
        pub fn deinit(self: *Self, allocator: Allocator) void {
            allocator.free(self.asBytes());
            self.* = undefined;
        }

        /// Calculate the number of bytes required to store this struct given the
        /// lengths of its `FlexibleArray` fields.
        pub fn calcSize(lens: Lengths) usize {
            const tail_field = field_info[field_info.len - 1].name;
            const tail_size = sizeOf(tail_field, lens);
            const tail_offset = offsetOf(tail_field, lens);

            return std.mem.alignForward(usize, tail_offset + tail_size, @alignOf(Layout));
        }

        /// Takes ownership of the passed in byte slice. The slice must be exactly
        /// the size of the struct with the given lengths.
        pub fn fromOwnedBytes(bytes: []align(@alignOf(Layout)) u8, lens: Lengths) Error!Self {
            if (bytes.len != calcSize(lens)) return error.InvalidLength;
            return .{
                .ptr = bytes.ptr,
                .lens = lens,
            };
        }

        /// Converts the byte buffer into a `StructuredSlice`. The caller is
        /// responsible for freeing the underlying bytes. Calling `deinit` on
        /// the returned value is illegal behavior. Returns an error when the
        /// slice is too small.
        pub fn fromBuffer(buf: []align(@alignOf(Layout)) u8, lens: Lengths) Error!Self {
            if (buf.len < calcSize(lens)) return error.InvalidLength;
            return .{
                .ptr = buf.ptr,
                .lens = lens,
            };
        }

        /// Returns a slice of the underlying bytes.
        pub fn asBytes(self: Self) []align(@alignOf(Layout)) u8 {
            return self.ptr[0..calcSize(self.lens)];
        }

        /// Copies all fields from one value into another. If a field is a
        /// `ResizableArray` and the lengths differ, the shorter length is used,
        /// possibly truncating the source array or leaving uninitialized memory
        /// in the destination array.
        pub fn copy(dest: Self, source: Self) Error!void {
            inline for (field_info) |field| {
                const tag = @field(FieldEnum(Layout), field.name);
                const source_field = source.get(tag);
                const dest_field = dest.get(tag);

                if (comptime isFlexibleArray(@FieldType(Layout, field.name))) {
                    const len = @min(source_field.len, dest_field.len);
                    @memcpy(dest_field[0..len], source_field[0..len]);
                } else {
                    dest_field.* = source_field.*;
                }
            }
        }

        /// Returns a pointer to the given field. If the field is a `FlexibleArray`, returns a slice of elements.
        pub fn get(self: Self, comptime field: FieldEnum(Layout)) blk: {
            const Field = @FieldType(Layout, @tagName(field));
            break :blk if (isFlexibleArray(Field)) []Field.Element else *Field;
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

        /// Returns the byte size of the given field, calculating the size of `FlexibleArray` fields using their length.
        fn sizeOf(comptime field_name: []const u8, lens: Lengths) usize {
            const Field = @FieldType(Layout, field_name);
            if (comptime isFlexibleArray(Field)) {
                return @sizeOf(Field.Element) * @field(lens, field_name);
            } else {
                return @sizeOf(Field);
            }
        }

        /// Returns the byte alignment of the given field.
        fn alignOf(comptime field_name: []const u8) usize {
            return std.meta.fieldInfo(Layout, @field(FieldEnum(Layout), field_name)).alignment;
        }
    };
}

test "FlexibleArray alignment" {
    try testing.expectEqual(16, @alignOf(FlexibleArray(u128)));
    try testing.expectEqual(8, @alignOf(FlexibleArray(u64)));
    try testing.expectEqual(4, @alignOf(FlexibleArray(u32)));
    try testing.expectEqual(2, @alignOf(FlexibleArray(u16)));
    try testing.expectEqual(1, @alignOf(FlexibleArray(u8)));
}

test "FlexibleArray alignment as a field" {
    const fields = @typeInfo(struct {
        a: FlexibleArray(u128),
        b: FlexibleArray(u64),
        c: FlexibleArray(u32),
        d: FlexibleArray(u16),
        u: FlexibleArray(u8),
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
        tail: FlexibleArray(u8),
    };
    const MyType = StructuredSlice(Layout);

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
    const MyType = StructuredSlice(struct {
        head: Head,
        first: FlexibleArray(u32),
        middle: Middle,
        second: FlexibleArray(u8),
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

    var new = try MyType.init(testing.allocator, .{
        .first = 3,
        .second = 5,
    });
    defer new.deinit(testing.allocator);
    try new.copy(my_type);

    first = new.get(.first);
    first[2] = 0xF00B42;
    second = new.get(.second);
    second[4] = 0x42;

    try testing.expectEqualDeep(&Head{ .head_val = 0xAA }, new.get(.head));
    try testing.expectEqual(3, new.get(.first).len);
    try testing.expectEqualSlices(u32, &.{ 0xC0FFEE, 0xBEEF, 0xF00B42 }, new.get(.first));
    try testing.expectEqualDeep(&Middle{ .middle_val = 0xBB }, new.get(.middle));
    try testing.expectEqual(5, new.get(.second).len);
    try testing.expectEqualSlices(u8, &.{ 0xC0, 0xDE, 0xD0, 0x0D, 0x42 }, new.get(.second));
    try testing.expectEqualDeep(&Tail{ .tail_val = 0xCC }, new.get(.tail));
}

test "extern struct" {
    const Bytes = StructuredSlice(extern struct {
        a: u8,
        b: u8 align(4),
        c: FlexibleArray(u8),
        d: FlexibleArray(u128),
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

    var new = try Bytes.init(testing.allocator, .{
        .c = 512,
        .d = 256,
    });
    defer new.deinit(testing.allocator);
    try new.copy(val);

    try testing.expectEqual(512, new.get(.c).len);
    try testing.expectEqual(256, new.get(.d).len);
    try testing.expectEqualSlices(u8, &.{ 0xC0, 0xFF, 0xEE }, new.get(.c)[0..3]);
    try testing.expectEqualSlices(u128, &.{0xBEEF}, new.get(.d)[0..1]);
}

test "fromOwnedBytes" {
    var packet = [_]u16{
        4,
        0xD00D,
        0xCAFE,
        0xBEEF,
        0xDEAD,
    };
    const Bytes = StructuredSlice(struct {
        len: u16,
        data: FlexibleArray(u16),
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

    const Bytes = StructuredSlice(struct {
        len: u16,
        data: FlexibleArray(u16),
    });

    const bytes = Bytes{
        .ptr = std.mem.asBytes(packet[0..]),
        .lens = .{
            .data = 4,
        },
    };

    try testing.expectEqualSlices(u8, std.mem.asBytes(packet[0..]), bytes.asBytes());
}

test "fromBuffer" {
    var buf: [1024]u8 align(2) = undefined;

    const Bytes = StructuredSlice(struct {
        len: u16,
        data: FlexibleArray(u16),
    });

    const bytes = try Bytes.fromBuffer(@ptrCast(buf[0..]), .{ .data = 4 });
    const data = bytes.get(.data);
    data[0] = 0xD00D;
    data[1] = 0xCAFE;
    data[2] = 0xBEEF;
    data[3] = 0xDEAD;

    try testing.expectEqualSlices(u16, &.{ 0xD00D, 0xCAFE, 0xBEEF, 0xDEAD }, bytes.get(.data));
}

const std = @import("std");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;
const FieldEnum = std.meta.FieldEnum;
const mem = std.mem;
const Struct = std.builtin.Type.Struct;
const StructField = std.builtin.Type.StructField;
const testing = std.testing;

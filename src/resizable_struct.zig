//! Structs with runtime-sized array fields.
//!
//! This module provides `ResizableStruct` for creating heap-allocated types that can be sized at runtime
//! and `ResizableArray` for marking the fields on that struct that are variable-length arrays.

/// This type is zero sized and has no methods. It exists as an API for `ResizableStruct`,
/// indicating which fields are runtime sized arrays of elements.
pub fn ResizableArray(comptime T: type) type {
    return struct {
        pub const Element = T;
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
            @compileError("Packed structs can not be used with `ResizableStruct`.");
        }
        if (@typeInfo(Layout).@"struct".layout == .@"extern") {
            @compileError("Extern structs can not be used with `ResizableStruct`.");
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

        /// The struct alignment - max alignment of all fields.
        const Alignment = blk: {
            var alignment = 0;
            for (field_info) |field| {
                alignment = @max(alignment, field.alignment);
            }
            break :blk alignment;
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
        ptr: [*]align(Alignment) u8,

        /// The length of each `ResizableArray` field.
        lens: Lengths,

        /// Initializes a new instance of the struct with the given lengths of its `ResizableArray` fields.
        pub fn init(allocator: Allocator, lens: Lengths) Oom!Self {
            const size = calcSize(lens);
            const bytes = try allocator.alignedAlloc(u8, Alignment, size);

            return Self{ .ptr = bytes.ptr, .lens = lens };
        }

        /// Deinitializes the struct, freeing its memory.
        pub fn deinit(self: *Self, allocator: Allocator) void {
            allocator.free(self.ptr[0..calcSize(self.lens)]);
            self.* = undefined;
        }

        /// Resizes the struct. Invalidates element pointers if relocation is needed.
        pub fn resize(self: *Self, allocator: Allocator, new_lens: Lengths) Oom!void {
            if (std.meta.eql(self.lens, new_lens)) return;

            // For now, we always reallocate when resizing. We could try to support resizing
            // in place, but the added complexity seems unlikely to be worth it for most use cases.
            const new_size = calcSize(new_lens);
            const new_bytes = try allocator.alignedAlloc(u8, Alignment, new_size);

            inline for (field_info) |field| {
                const old_field_offset = offsetOf(self.lens, field.name);
                const old_field_size = sizeOf(self.lens, field.name);
                const old_field_bytes = self.ptr[old_field_offset .. old_field_offset + old_field_size];

                const new_field_offset = offsetOf(new_lens, field.name);
                const new_field_size = sizeOf(new_lens, field.name);
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
            const start = offsetOf(self.lens, @tagName(field));
            const end = start + sizeOf(self.lens, @tagName(field));
            const bytes = self.ptr[start..end];

            return @ptrCast(@alignCast(bytes));
        }

        /// Returns the byte offset of the given field.
        fn offsetOf(lens: Lengths, comptime field_name: []const u8) usize {
            var offset: usize = 0;
            inline for (field_info) |f| {
                if (comptime std.mem.eql(u8, f.name, field_name)) {
                    return offset;
                } else {
                    offset += sizeOf(lens, f.name);
                }
            }
            unreachable;
        }

        /// Returns the byte size of the given field, calculating the size of `ResizableArray` fields using their length.
        fn sizeOf(lens: Lengths, comptime field_name: []const u8) usize {
            const Field = @FieldType(Layout, field_name);
            if (comptime isResizableArray(Field)) {
                return @sizeOf(Field.Element) * @field(lens, field_name);
            } else {
                return @sizeOf(Field);
            }
        }

        /// Returns the byte alignment of the given field.
        fn alignOf(comptime field_name: []const u8) usize {
            inline for (field_info) |field| {
                if (comptime std.mem.eql(u8, field.name, field_name)) {
                    return field.alignment;
                }
            }
            unreachable;
        }

        /// Calculate the byte size of this struct given the lengths of its `ResizableArray` fields.
        fn calcSize(lens: Lengths) usize {
            const tail_name = field_info[field_info.len - 1].name;
            const tail_size = sizeOf(lens, tail_name);
            const tail_offset = offsetOf(lens, tail_name);

            return std.mem.alignForward(usize, tail_offset + tail_size, Alignment);
        }
    };
}

test "Alignment is max" {
    const MyType = ResizableStruct(struct {
        a: u8,
        b: u16,
        c: u32,
        d: u128,
        u: u64,
    });

    try std.testing.expectEqual(@alignOf(u128), MyType.Alignment);
}

test "calcSize is multiple of alignment" {
    const Alignment = 8;
    const MyType = ResizableStruct(struct {
        head: u128 align(Alignment),
        tail: ResizableArray(u8),
    });

    try std.testing.expectEqual(@sizeOf(u128), MyType.calcSize(.{
        .tail = 0,
    }));

    inline for (1..Alignment + 1) |i| {
        try std.testing.expectEqual(@sizeOf(u128) + Alignment, MyType.calcSize(.{
            .tail = i,
        }));
    }

    try std.testing.expectEqual(@sizeOf(u128) + 2 * Alignment, MyType.calcSize(.{
        .tail = Alignment + 1,
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

const std = @import("std");
const Allocator = std.mem.Allocator;
const FieldEnum = std.meta.FieldEnum;
const mem = std.mem;
const Oom = std.mem.Allocator.Error;
const Struct = std.builtin.Type.Struct;
const StructField = std.builtin.Type.StructField;
const testing = std.testing;

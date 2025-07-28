# resizable-struct

This library provides types for creating structs with runtime sized array fields.

## Docs

Documentation is hosted on GitHub pages: https://tristanpemble.github.io/resizable-struct/

## Usage

To create a resizable struct, wrap your struct type with `StructuredSlice(T)`. Mark
variable-length array fields using `FlexibleArray(Elem)` - you can have multiple
resizable arrays within a single struct, and they can be mixed with regular fixed-size
wherever you want.

```zig
const Bytes = StructuredSlice(struct {
    header: u32,               // Fixed field
    items: FlexibleArray(u8),  // Variable-length array
    middle: u32,
    extra: FlexibleArray(u16), // Another variable-length array
    footer: u32,               // Another fixed field
});

// Create with 10 items and 5 extra
var bytes = try Bytes.init(allocator, .{ .items = 10, .extra = 5 });
defer bytes.deinit(allocator);

// Access fields
const header = bytes.get(.header);
header.* = 0xFF;
const items = bytes.get(.items);  // Returns []u8 slice
items[0] = 42;

// Grow items to 20 and shrink extra at the same time
try bytes.resize(allocator, .{ .items = 20, .extra = 2 });
```

## Acknowledgments

Discussions with &lt;triallax&gt; and &lt;andrewrk&gt; on the `#zig` IRC channel led to the design of this library.

## License

MIT

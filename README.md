# resizable-struct

This library provides types for creating structs with runtime sized array fields.

## Docs

Documentation is hosted on GitHub pages: https://tristanpemble.github.io/resizable-struct/

## Usage

To create a structured slice, wrap your struct type with `StructuredSlice(T)`. Mark
the runtime sized array fields using `FlexibleArray(Elem)` - you can have multiple
FlexibleArrays within a single struct, and they can be mixed with regular fixed-size
fields wherever you want.

```zig
const Bytes = StructuredSlice(struct {
    header: u32,               // Fixed field
    items: FlexibleArray(u8),  // Runtime sized array
    middle: u32,
    extra: FlexibleArray(u16), // Another runtime sized array
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

// Create a new slice with different lengths and copy the data from the old one
var new_bytes = try Bytes.init(allocator, .{ .items = 20, .extra = 2 });
defer new_bytes.deinit(allocator);
new_bytes.copy(bytes);
```

## Acknowledgments

Discussions with &lt;triallax&gt; and &lt;andrewrk&gt; on the `#zig` IRC channel led to the design of this library.

## License

MIT

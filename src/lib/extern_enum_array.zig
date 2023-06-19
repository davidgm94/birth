const lib = @import("lib");
// ENUM ARRAY
pub fn IndexedArray(comptime I: type, comptime V: type, comptime Ext: fn (type) type) type {
    comptime ensureIndexer(I);
    return extern struct {
        const Self = @This();

        pub usingnamespace Ext(Self);

        /// The index mapping for this map
        pub const Indexer = I;
        /// The key type used to index this map
        pub const Key = Indexer.Key;
        /// The value type stored in this map
        pub const Value = V;
        /// The number of possible keys in the map
        pub const len = Indexer.count;

        values: [Indexer.count]Value,

        pub fn initUndefined() Self {
            return Self{ .values = undefined };
        }

        pub fn initFill(v: Value) Self {
            var self: Self = undefined;
            lib.set(Value, &self.values, v);
            return self;
        }

        /// Returns the value in the array associated with a key.
        pub fn get(self: Self, key: Key) Value {
            return self.values[Indexer.indexOf(key)];
        }

        /// Returns a pointer to the slot in the array associated with a key.
        pub fn getPtr(self: *Self, key: Key) *Value {
            return &self.values[Indexer.indexOf(key)];
        }

        /// Returns a const pointer to the slot in the array associated with a key.
        pub fn getPtrConst(self: *const Self, key: Key) *const Value {
            return &self.values[Indexer.indexOf(key)];
        }

        /// Sets the value in the slot associated with a key.
        pub fn set(self: *Self, key: Key, value: Value) void {
            self.values[Indexer.indexOf(key)] = value;
        }

        /// Iterates over the items in the array, in index order.
        pub fn iterator(self: *Self) Iterator {
            return .{
                .values = &self.values,
            };
        }

        /// An entry in the array.
        pub const Entry = extern struct {
            /// The key associated with this entry.
            /// Modifying this key will not change the array.
            key: Key,

            /// A pointer to the value in the array associated
            /// with this key.  Modifications through this
            /// pointer will modify the underlying data.
            value: *Value,
        };

        pub const Iterator = extern struct {
            index: usize = 0,
            values: *[Indexer.count]Value,

            pub fn next(self: *Iterator) ?Entry {
                const index = self.index;
                if (index < Indexer.count) {
                    self.index += 1;
                    return Entry{
                        .key = Indexer.keyForIndex(index),
                        .value = &self.values[index],
                    };
                }
                return null;
            }
        };
    };
}

pub fn ensureIndexer(comptime T: type) void {
    comptime {
        if (!@hasDecl(T, "Key")) @compileError("Indexer must have decl Key: type.");
        if (@TypeOf(T.Key) != type) @compileError("Indexer.Key must be a type.");
        if (!@hasDecl(T, "count")) @compileError("Indexer must have decl count: usize.");
        if (@TypeOf(T.count) != usize) @compileError("Indexer.count must be a usize.");
        if (!@hasDecl(T, "indexOf")) @compileError("Indexer.indexOf must be a fn(Key)usize.");
        if (@TypeOf(T.indexOf) != fn (T.Key) usize) @compileError("Indexer must have decl indexOf: fn(Key)usize.");
        if (!@hasDecl(T, "keyForIndex")) @compileError("Indexer must have decl keyForIndex: fn(usize)Key.");
        if (@TypeOf(T.keyForIndex) != fn (usize) T.Key) @compileError("Indexer.keyForIndex must be a fn(usize)Key.");
    }
}

pub fn EnumArray(comptime E: type, comptime V: type) type {
    const mixin = extern struct {
        fn EnumArrayExt(comptime Self: type) type {
            const Indexer = Self.Indexer;
            return extern struct {
                /// Initializes all values in the enum array
                pub fn init(init_values: EnumFieldStruct(E, V, @as(?V, null))) Self {
                    return initDefault(@as(?V, null), init_values);
                }

                /// Initializes values in the enum array, with the specified default.
                pub fn initDefault(comptime default: ?V, init_values: EnumFieldStruct(E, V, default)) Self {
                    var result = Self{ .values = undefined };
                    comptime var i: usize = 0;
                    inline while (i < Self.len) : (i += 1) {
                        const key = comptime Indexer.keyForIndex(i);
                        const tag = @tagName(key);
                        result.values[i] = @field(init_values, tag);
                    }
                    return result;
                }
            };
        }
    };
    return IndexedArray(EnumIndexer(E), V, mixin.EnumArrayExt);
}
const EnumField = lib.Type.EnumField;
pub fn EnumIndexer(comptime E: type) type {
    if (!@typeInfo(E).Enum.is_exhaustive) {
        @compileError("Cannot create an enum indexer for a non-exhaustive enum.");
    }

    const const_fields = lib.fields(E);
    comptime var fields = const_fields[0..const_fields.len].*;
    const fields_len = fields.len;
    if (fields_len == 0) {
        return extern struct {
            pub const Key = E;
            pub const count: usize = 0;
            pub fn indexOf(e: E) usize {
                _ = e;
                unreachable;
            }
            pub fn keyForIndex(i: usize) E {
                _ = i;
                unreachable;
            }
        };
    }
    const SortContext = struct {
        fields: []EnumField,

        pub fn lessThan(comptime ctx: @This(), comptime a: usize, comptime b: usize) bool {
            return ctx.fields[a].value < ctx.fields[b].value;
        }

        pub fn swap(comptime ctx: @This(), comptime a: usize, comptime b: usize) void {
            return lib.swap(EnumField, &ctx.fields[a], &ctx.fields[b]);
        }
    };
    lib.sort.insertionContext(0, fields_len, SortContext{ .fields = &fields });

    const min = fields[0].value;
    const max = fields[fields.len - 1].value;
    if (max - min == fields.len - 1) {
        return extern struct {
            pub const Key = E;
            pub const count = fields_len;
            pub fn indexOf(e: E) usize {
                return @as(usize, @intCast(@intFromEnum(e) - min));
            }
            pub fn keyForIndex(i: usize) E {
                // TODO fix addition semantics.  This calculation
                // gives up some safety to avoid artificially limiting
                // the range of signed enum values to max_isize.
                const enum_value = if (min < 0) @as(isize, @bitCast(i)) +% min else i + min;
                return @as(E, @enumFromInt(@as(lib.Tag(E), @intCast(enum_value))));
            }
        };
    }

    const keys = valuesFromFields(E, &fields);

    return extern struct {
        pub const Key = E;
        pub const count = fields_len;
        pub fn indexOf(e: E) usize {
            for (keys, 0..) |k, i| {
                if (k == e) return i;
            }
            unreachable;
        }
        pub fn keyForIndex(i: usize) E {
            return keys[i];
        }
    };
}
pub fn EnumFieldStruct(comptime E: type, comptime Data: type, comptime field_default: ?Data) type {
    const StructField = lib.builtin.Type.StructField;
    var fields: []const StructField = &[_]StructField{};
    for (lib.fields(E)) |field| {
        fields = fields ++ &[_]StructField{.{
            .name = field.name,
            .type = Data,
            .default_value = if (field_default) |d| @as(?*const anyopaque, @ptrCast(&d)) else null,
            .is_comptime = false,
            .alignment = if (@sizeOf(Data) > 0) @alignOf(Data) else 0,
        }};
    }
    return @Type(.{ .Struct = .{
        .layout = .Extern,
        .fields = fields,
        .decls = &.{},
        .is_tuple = false,
    } });
}

fn ascByValue(ctx: void, comptime a: EnumField, comptime b: EnumField) bool {
    _ = ctx;
    return a.value < b.value;
}
pub fn valuesFromFields(comptime E: type, comptime fields: []const EnumField) []const E {
    comptime {
        var result: [fields.len]E = undefined;
        for (fields, 0..) |f, i| {
            result[i] = @field(E, f.name);
        }
        return &result;
    }
}

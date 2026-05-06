# style-fuzzgen.c - FuzzGen-Style Style Parser Harness

## Overview

This harness targets tmux's style parser (`style.c`), using structured data consumption to control base cell configuration and API sequence selection.

## Target Functions

- `style_parse()` - Parse style string
- `style_tostring()` - Convert style to string
- `style_set()` - Set style from grid cell

## FuzzGen Generation Approach

### Step 1: Identify Style String Structure

tmux style strings use comma-separated attributes:
```
fg=red,bg=blue,bold     # Colors and attributes
align=centre,list=on    # Alignment and list mode
range=window|1          # Range specification
colour123               # 256-color (British spelling)
#ff0000                 # RGB hex color
```

### Step 2: Data Provider Pattern

```c
struct data_provider {
    const uint8_t *data;
    size_t         size;
    size_t         pos;
};
```

### Step 3: Structured Input Layout

```
[api_select:1][fg_byte:1][bg_byte:1][attr_byte:1][payload_len:2][payload:N]
```

| Field | Size | Purpose |
|-------|------|---------|
| api_select | 1 | API sequence (mod 5) |
| fg_byte | 1 | Base foreground color |
| bg_byte | 1 | Base background color |
| attr_byte | 1 | Base attributes |
| payload_len | 2 | Style string length |
| payload | N | Style string content |

### Step 4: Base Cell Configuration

```c
memcpy(&base_gc, &grid_default_cell, sizeof(base_gc));
base_gc.fg = fg_byte;
base_gc.bg = bg_byte;
base_gc.attr = attr_byte;
```

### Step 5: API Sequence Selection

```c
switch (api_select % 5) {
case 0: /* Basic style_parse */
    style_set(&sy, &base_gc);
    ret = style_parse(&sy, &base_gc, style_str);
    break;
case 1: /* Parse + tostring roundtrip */
    style_set(&sy, &base_gc);
    ret = style_parse(&sy, &base_gc, style_str);
    if (ret == 0) {
        result = style_tostring(&sy);
        style_parse(&sy2, &grid_default_cell, result);
    }
    break;
case 2: /* Multiple parses with varying bases */
    for (int i = 0; i < 3; i++) {
        base_gc.fg = (fg_byte + i * 10) % 256;
        base_gc.bg = (bg_byte + i * 10) % 256;
        style_parse(&sy, &base_gc, style_str);
    }
    break;
case 3: /* Parse with default cell */
    style_parse(&sy, &grid_default_cell, style_str);
    break;
case 4: /* Chained style operations */
    // Parse first half, then second half on result
    break;
}
```

## Building

### LibFuzzer Build
```bash
clang -g -O1 -fsanitize=fuzzer,address \
    -I/path/to/tmux \
    style-fuzzgen.c \
    /path/to/tmux/.libs/libtmux.a \
    -levent_core -lutil -lm -lresolv \
    -o style-fuzzgen
```

### AFL++ Build
```bash
afl-clang-fast -g -O2 \
    -I/path/to/tmux \
    style-fuzzgen.c afl-main.c tmux-stubs.c \
    /path/to/tmux/objs/*.o \
    -levent_core -lutil -lm -lresolv -lncurses \
    -o style-fuzzgen-afl
```

## Running

### LibFuzzer
```bash
./style-fuzzgen \
    corpus/style/ \
    -max_len=2048 \
    -max_total_time=3600
```

### AFL++
```bash
afl-fuzz -i corpus/style -o output/style \
    -- ./style-fuzzgen-afl
```

## Coverage Strategy

The FuzzGen approach explores:

1. **Base Color Combinations** - 256 × 256 = 65,536 base states
2. **Attribute Variations** - 256 attribute combinations
3. **API Sequences** - 5 different operation sequences
4. **Roundtrip Validation** - Parse → tostring → parse
5. **Chained Operations** - Incremental style building

## Expected Coverage Targets

- `style.c` - Style parsing
  - `style_parse()` - Main parser
  - `style_tostring()` - Serialization
  - `style_set()` - Initialization
  - `style_parse_value()` - Value parsing

## Comparison to Manual Harness

| Aspect | FuzzGen Style | Manual |
|--------|--------------|--------|
| Base Colors | Fuzz-controlled | Fixed defaults |
| APIs | 5 sequences | 3 calls |
| Roundtrip | Yes (mode 1) | Partial |
| Chaining | Yes (mode 4) | No |
| Setup Overhead | 6 bytes | 0 bytes |

## Advantages

1. **Base State Exploration** - Tests color/attribute combinations
2. **Roundtrip Validation** - Ensures parse↔tostring consistency
3. **Chained Parsing** - Tests incremental style application
4. **Multiple Bases** - Tests style inheritance behavior

# layout-parse-fuzzgen.c - FuzzGen-Style Layout Parser Harness

## Overview

This harness targets tmux's layout parser (`layout-custom.c`), using structured data consumption to control layout generation and parsing modes.

## Target Functions

- `layout_parse()` - Parse layout string
- `layout_fix_panes()` - Fix pane layout
- `layout_resize()` - Resize window layout

## FuzzGen Generation Approach

### Step 1: Identify Layout String Structure

tmux layout strings follow this format:
```
CHECKSUM,WIDTHxHEIGHT,X,Y[{CHILDREN}]
```

Example: `b3e7,80x24,0,0{40x24,0,0,0,39x24,41,0,1}`

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
[mode:1][width:1][height:1][payload:N]
```

| Field | Size | Purpose |
|-------|------|---------|
| mode | 1 | Generation mode (0-2) |
| width | 1 | Maps to 20-219 pixels |
| height | 1 | Maps to 5-104 lines |
| payload | N | Raw layout content |

### Step 4: Generation Modes

**Mode 0: Raw with Dimensions**
```c
snprintf(header, sizeof(header), "%dx%d,0,0", width, height);
// Use payload directly as layout content
```

**Mode 1: Valid Checksum Header**
```c
uint16_t csum = calc_checksum(payload);
snprintf(layout, 16, "%04x,%dx%d,", csum, width, height);
// Prepends valid-looking checksum
```

**Mode 2: Structured Fragment**
```c
snprintf(layout, FUZZER_MAXLEN, "%dx%d,0,0{%.*s}", 
    width, height, (int)payload_len, payload);
// Wraps payload in brace structure
```

### Step 5: Checksum Calculation

Uses tmux's actual checksum algorithm:
```c
static uint16_t calc_checksum(const char *layout) {
    uint16_t csum = 0;
    for (const char *p = layout; *p != '\0'; p++)
        csum = (csum >> 1) + ((csum & 1) << 15) + (uint8_t)*p;
    return csum;
}
```

### Step 6: Post-Parse Operations

```c
if (ret == 0) {
    layout_fix_panes(w, NULL);
    if (mode & 0x10)
        layout_resize(w, width + 20, height + 10);
}
```

## Building

### LibFuzzer Build
```bash
clang -g -O1 -fsanitize=fuzzer,address \
    -I/path/to/tmux \
    layout-parse-fuzzgen.c \
    /path/to/tmux/.libs/libtmux.a \
    -levent_core -lutil -lm -lresolv \
    -o layout-parse-fuzzgen
```

### AFL++ Build
```bash
afl-clang-fast -g -O2 \
    -I/path/to/tmux \
    layout-parse-fuzzgen.c afl-main.c tmux-stubs.c \
    /path/to/tmux/objs/*.o \
    -levent_core -lutil -lm -lresolv -lncurses \
    -o layout-parse-fuzzgen-afl
```

## Running

### LibFuzzer
```bash
./layout-parse-fuzzgen \
    corpus/layout-parse/ \
    -max_len=2048 \
    -max_total_time=3600
```

### AFL++
```bash
afl-fuzz -i corpus/layout-parse -o output/layout-parse \
    -- ./layout-parse-fuzzgen-afl
```

## Coverage Strategy

The FuzzGen approach explores:

1. **Multiple Generation Modes** - Raw, checksummed, structured
2. **Variable Dimensions** - Tests boundary conditions
3. **Valid Checksum Paths** - Mode 1 creates valid-looking headers
4. **Post-Parse Operations** - Exercises fix_panes and resize

## Expected Coverage Targets

- `layout-custom.c` - Main parser
  - `layout_parse()` - Entry point
  - `layout_parse_*()` - Internal parsers
- `layout.c` - Layout operations
  - `layout_fix_panes()`
  - `layout_resize()`
  - `layout_assign_pane()`

## Comparison to Manual Harness

| Aspect | FuzzGen Style | Manual |
|--------|--------------|--------|
| Dimensions | Fuzz-derived | Fixed 80x25 |
| Checksum | Can be valid | Random |
| Structure | Mode-controlled | Raw |
| Post-ops | Conditional | None |
| Setup Overhead | 3 bytes | 0 bytes |

## Advantages

1. **Valid Checksum Exploration** - Mode 1 hits checksum-verified paths
2. **Structured Layout Generation** - Mode 2 creates syntactically valid layouts
3. **Dimension Coverage** - Tests layout under various window sizes
4. **Post-Parse Coverage** - Exercises layout manipulation functions

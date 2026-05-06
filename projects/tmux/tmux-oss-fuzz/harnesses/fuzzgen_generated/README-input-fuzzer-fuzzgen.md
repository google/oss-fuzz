# input-fuzzer-fuzzgen.c - FuzzGen-Style Input Parser Harness

## Overview

This harness targets tmux's terminal input parser (`input.c`), using a FuzzGen-inspired FuzzedDataProvider pattern to control test configuration through fuzz input.

## Target Functions

- `input_parse_buffer()` - Main escape sequence parser
- `input_init()` - Initialize input context
- `window_create()` / `window_add_pane()` - Window/pane setup

## FuzzGen Generation Approach

### Step 1: Identify Target Parameters

FuzzGen analyzes how `input_parse_buffer()` is called and identifies configurable parameters:

```c
/* From API analysis */
window_create(width, height, 0, flags);  /* Dimensions are parameters */
input_parse_buffer(wp, data, len);        /* Data is the main input */
```

### Step 2: FuzzedDataProvider Implementation

```c
struct fuzzed_data {
    const uint8_t *data;
    size_t size;
    size_t offset;
};
```

Consumption functions:
- `fd_consume_byte()` - Single bytes
- `fd_consume_uint16()` - 16-bit integers
- `fd_consume_uint32_in_range()` - Bounded integers
- `fd_consume_bool()` - Boolean flags
- `fd_consume_bytes()` - Byte arrays

### Step 3: Structured Input Layout

```
[width:4][height:4][flags:1][opt_allow_rename:1][opt_set_clipboard:1+4][escape_data:N]
```

| Offset | Size | Field | Range |
|--------|------|-------|-------|
| 0 | 4 | pane_width | 10-200 |
| 4 | 4 | pane_height | 5-100 |
| 8 | 1 | window_flags | 0x00-0x0F |
| 9 | 1 | allow_rename | 0/1 |
| 10 | 1+4 | set_clipboard | 0/1, then 0-2 |
| 15+ | N | escape_sequences | Raw bytes |

### Step 4: Parameter Derivation

```c
/* Derive dimensions from fuzz input */
pane_width = fd_consume_uint32_in_range(&fd, 10, 200);
pane_height = fd_consume_uint32_in_range(&fd, 5, 100);

/* Derive option values */
if (fd_consume_bool(&fd)) {
    options_set_number(global_w_options, "allow-rename", 1);
}
```

### Step 5: Post-Processing

FuzzGen observes that consumer programs call these after parsing:
```c
while (cmdq_next(NULL) != 0);
event_base_loop(libevent, EVLOOP_NONBLOCK);
```

## Building

### LibFuzzer Build
```bash
clang -g -O1 -fsanitize=fuzzer,address \
    -I/path/to/tmux \
    input-fuzzer-fuzzgen.c \
    /path/to/tmux/.libs/libtmux.a \
    -levent_core -lutil -lm -lresolv \
    -o input-fuzzer-fuzzgen
```

### AFL++ Build
```bash
afl-clang-fast -g -O2 \
    -I/path/to/tmux \
    input-fuzzer-fuzzgen.c afl-main.c tmux-stubs.c \
    /path/to/tmux/objs/*.o \
    -levent_core -lutil -lm -lresolv -lncurses \
    -o input-fuzzer-fuzzgen-afl
```

## Running

### LibFuzzer
```bash
./input-fuzzer-fuzzgen \
    corpus/input-parse/ \
    -max_len=512 \
    -dict=input-fuzzer.dict \
    -max_total_time=3600
```

### AFL++
```bash
afl-fuzz -i corpus/input-parse -o output/input-parse \
    -- ./input-fuzzer-fuzzgen-afl
```

## Coverage Strategy

The FuzzGen approach explores:

1. **Variable Dimensions** - Tests size edge cases (10x5 to 200x100)
2. **Window Flags** - Explores 16 flag combinations
3. **Option Variations** - allow-rename and set-clipboard
4. **Full Escape Sequences** - Remaining bytes as terminal input

## Expected Coverage Targets

- `input.c` - Main state machine
  - `input_csi_dispatch_*` - CSI sequence handlers
  - `input_osc_*` - OSC sequence handlers
  - `input_dcs_*` - DCS sequence handlers
- `screen.c` - Screen operations
- `grid.c` - Grid manipulation
- `screen-write.c` - Character rendering

## Key Differences from Manual Harness

| Aspect | FuzzGen Style | Manual |
|--------|--------------|--------|
| Pane Dimensions | Fuzz-derived (10-200 x 5-100) | Fixed (80x25) |
| Window Flags | Fuzz-controlled | None |
| Option Config | Dynamic from input | Static |
| Setup Overhead | ~15 bytes | 0 bytes |
| Exploration | Configuration + data | Data only |

## Advantages

1. **Edge Case Discovery** - Variable dimensions reveal size-dependent bugs
2. **Configuration Coverage** - Tests option interactions
3. **Reproducibility** - Configuration encoded in input
4. **Structured Exploration** - Separates control from data

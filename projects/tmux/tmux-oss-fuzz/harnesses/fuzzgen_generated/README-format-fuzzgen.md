# format-fuzzgen.c - FuzzGen-Style Format Expander Harness

## Overview

This harness targets tmux's format string expansion (`format.c`), using structured data consumption to control format flags, variable injection, and API selection.

## Target Functions

- `format_create()` - Create format tree
- `format_add()` - Add variables to tree
- `format_expand()` - Expand format string
- `format_expand_time()` - Expand with time formatting
- `format_free()` - Free format tree

## FuzzGen Generation Approach

### Step 1: Identify Format String Structure

tmux format strings use:
- Variables: `#{variable_name}`
- Commands: `#(shell_command)`
- Styles: `#[style_spec]`
- Conditionals: `#{?cond,true,false}`
- Comparisons: `#{==:a,b}`, `#{!=:a,b}`

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
[api_select:1][flag_byte:1][var_ctrl:1][payload_len:2][payload:N]
```

| Field | Size | Purpose |
|-------|------|---------|
| api_select | 1 | API to test (mod 3) |
| flag_byte | 1 | FORMAT_* flags |
| var_ctrl | 1 | Variable injection bitmap |
| payload_len | 2 | Format string length |
| payload | N | Format string content |

### Step 4: Flag Configuration

```c
flags = FORMAT_NONE;
if (flag_byte & 0x01) flags |= FORMAT_NOJOBS;
if (flag_byte & 0x02) flags |= FORMAT_VERBOSE;
if (flag_byte & 0x04) flags |= FORMAT_FORCE;
if (flag_byte & 0x08) flags |= FORMAT_STATUS;
```

### Step 5: Variable Injection

```c
static const char *var_names[] = {
    "test_var1", "test_var2", "test_var3", "test_var4",
    "pane_id", "window_index", "session_name", "host"
};

for (i = 0; i < NUM_VARS; i++) {
    if (var_ctrl & (1 << i)) {
        format_add(ft, var_names[i], "%s", "fuzz_value");
    }
}
```

### Step 6: API Selection

```c
switch (api_select % 3) {
case 0: /* format_expand */
    result = format_expand(ft, format);
    break;
case 1: /* format_expand_time */
    result = format_expand_time(ft, format);
    break;
case 2: /* Multiple expansions */
    for (i = 0; i < 3; i++) {
        result = format_expand(ft, format);
        free(result);
    }
    break;
}
```

## Building

### LibFuzzer Build
```bash
clang -g -O1 -fsanitize=fuzzer,address \
    -I/path/to/tmux \
    format-fuzzgen.c \
    /path/to/tmux/.libs/libtmux.a \
    -levent_core -lutil -lm -lresolv \
    -o format-fuzzgen
```

### AFL++ Build
```bash
afl-clang-fast -g -O2 \
    -I/path/to/tmux \
    format-fuzzgen.c afl-main.c tmux-stubs.c \
    /path/to/tmux/objs/*.o \
    -levent_core -lutil -lm -lresolv -lncurses \
    -o format-fuzzgen-afl
```

## Running

### LibFuzzer
```bash
./format-fuzzgen \
    corpus/format/ \
    -max_len=4096 \
    -max_total_time=3600
```

### AFL++
```bash
afl-fuzz -i corpus/format -o output/format \
    -- ./format-fuzzgen-afl
```

## Coverage Strategy

The FuzzGen approach explores:

1. **All Expansion Flags** - 16 combinations via flag_byte
2. **Variable Presence/Absence** - 256 variable combinations
3. **Multiple APIs** - expand vs expand_time vs repeated
4. **Repeated Expansion** - Tests expansion stability

## Expected Coverage Targets

- `format.c` - Main format expansion
  - `format_expand()` - Variable expansion
  - `format_expand_time()` - Time formatting
  - `format_parse_*()` - Format parsing
- `format-draw.c` - Format drawing

## Comparison to Manual Harness

| Aspect | FuzzGen Style | Manual |
|--------|--------------|--------|
| Flags | Fuzz-controlled | Fixed |
| Variables | 256 combinations | Fixed set |
| APIs | 3 modes | 2 calls |
| Repetition | Controlled | None |
| Setup Overhead | 5 bytes | 0 bytes |

## Advantages

1. **Flag Coverage** - Tests all FORMAT_* combinations
2. **Variable Interaction** - Tests presence/absence effects
3. **API Comparison** - Compares expand vs expand_time
4. **Stability Testing** - Repeated expansion mode

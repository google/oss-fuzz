# utf8-fuzzgen.c - FuzzGen-Style UTF-8 Harness

## Overview

This harness targets tmux's UTF-8 handling (`utf8.c`), using structured data consumption to generate UTF-8 sequences and select API functions.

## Target Functions

- `utf8_isvalid()` - Validate UTF-8 string
- `utf8_strvis()` - Visualize UTF-8 string
- `utf8_open()` / `utf8_append()` - Byte-by-byte parsing
- `utf8_towc()` - Convert to wide character
- `utf8_from_data()` / `utf8_to_data()` - Data conversion

## FuzzGen Generation Approach

### Step 1: Identify UTF-8 Byte Patterns

UTF-8 encoding uses specific byte patterns:
- ASCII: `0xxxxxxx` (0x00-0x7F)
- 2-byte: `110xxxxx 10xxxxxx`
- 3-byte: `1110xxxx 10xxxxxx 10xxxxxx`
- 4-byte: `11110xxx 10xxxxxx 10xxxxxx 10xxxxxx`

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
[api_select:1][seq_count:1][ctrl:1][b1:1][b2:1][b3:1]... (repeated)
```

| Field | Size | Purpose |
|-------|------|---------|
| api_select | 1 | API to test (0-4) |
| seq_count | 1 | Number of sequences (mod 64 + 1) |
| ctrl | 1 | Sequence type per entry |
| b1-b3 | 3 | Bytes for sequence generation |

### Step 4: UTF-8 Sequence Generation

```c
static size_t generate_utf8_seq(uint8_t ctrl, uint8_t b1, uint8_t b2, uint8_t b3, uint8_t *out) {
    switch (ctrl % 6) {
    case 0: /* ASCII */
        out[0] = b1 & 0x7F;
        return 1;
    case 1: /* 2-byte sequence */
        out[0] = 0xC0 | ((b1 >> 2) & 0x1F);
        out[1] = 0x80 | (b1 & 0x3F);
        return 2;
    case 2: /* 3-byte sequence */
        out[0] = 0xE0 | ((b1 >> 4) & 0x0F);
        out[1] = 0x80 | ((b1 << 2) & 0x3C) | ((b2 >> 6) & 0x03);
        out[2] = 0x80 | (b2 & 0x3F);
        return 3;
    case 3: /* 4-byte sequence */
        out[0] = 0xF0 | ((b1 >> 6) & 0x07);
        out[1] = 0x80 | ((b1 >> 0) & 0x3F);
        out[2] = 0x80 | ((b2 >> 2) & 0x3F);
        out[3] = 0x80 | ((b2 << 4) & 0x30) | (b3 & 0x0F);
        return 4;
    case 4: /* Invalid: overlong 2-byte */
        out[0] = 0xC0;
        out[1] = 0x80 | (b1 & 0x3F);
        return 2;
    case 5: /* Raw bytes (malformed) */
        out[0] = b1; out[1] = b2; out[2] = b3;
        return 3;
    }
}
```

### Step 5: API Selection

```c
switch (api_select % 5) {
case 0: utf8_isvalid(buffer); break;
case 1: utf8_strvis(vis_buf, buffer, buf_pos * 4, VIS_OCTAL); break;
case 2: /* utf8_open/append cycle */ break;
case 3: utf8_towc(&ud, &wc); break;
case 4: /* utf8_from_data/utf8_to_data roundtrip */ break;
}
```

## Building

### LibFuzzer Build
```bash
clang -g -O1 -fsanitize=fuzzer,address \
    -I/path/to/tmux \
    utf8-fuzzgen.c \
    /path/to/tmux/.libs/libtmux.a \
    -levent_core -lutil -lm -lresolv \
    -o utf8-fuzzgen
```

### AFL++ Build
```bash
afl-clang-fast -g -O2 \
    -I/path/to/tmux \
    utf8-fuzzgen.c afl-main.c tmux-stubs.c \
    /path/to/tmux/objs/*.o \
    -levent_core -lutil -lm -lresolv -lncurses \
    -o utf8-fuzzgen-afl
```

## Running

### LibFuzzer
```bash
./utf8-fuzzgen \
    corpus/utf8/ \
    -max_len=1024 \
    -max_total_time=3600
```

### AFL++
```bash
afl-fuzz -i corpus/utf8 -o output/utf8 \
    -- ./utf8-fuzzgen-afl
```

## Coverage Strategy

The FuzzGen approach explores:

1. **All UTF-8 Sequence Types** - 1 to 4 bytes plus invalid
2. **Multiple APIs** - Five different function groups
3. **Invalid Sequences** - Overlong, malformed patterns
4. **Sequence Count Variation** - 1 to 64 sequences per input

## Expected Coverage Targets

- `utf8.c` - Main UTF-8 handling
  - `utf8_isvalid()` - Validation logic
  - `utf8_open()` / `utf8_append()` - State machine
  - `utf8_strvis()` - Visualization
  - `utf8_towc()` - Wide char conversion
  - `utf8_from_data()` / `utf8_to_data()` - Data conversion

## Comparison to Manual Harness

| Aspect | FuzzGen Style | Manual |
|--------|--------------|--------|
| Sequence Generation | Structured (6 types) | Raw bytes |
| API Selection | Fuzz-controlled | All APIs |
| Invalid Patterns | Explicit (overlong) | Random |
| Sequence Count | Controlled (1-64) | Variable |
| Setup Overhead | 2 + 4*N bytes | 0 bytes |

## Advantages

1. **Structured UTF-8 Generation** - Creates valid-looking sequences
2. **Explicit Invalid Patterns** - Tests overlong rejection
3. **API Coverage** - Exercises all UTF-8 functions
4. **Reproducible** - Configuration in input bytes

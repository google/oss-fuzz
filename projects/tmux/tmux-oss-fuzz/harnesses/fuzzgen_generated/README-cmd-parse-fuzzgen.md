# cmd-parse-fuzzgen.c - FuzzGen-Style Command Parser Harness

## Overview

This harness targets tmux's command parser (`cmd-parse.y`), using a FuzzGen-inspired structured data consumption approach.

## Target Functions

- `cmd_parse_from_buffer()` - Parse commands from a buffer
- `cmd_parse_from_string()` - Parse commands from a string
- `cmd_list_free()` - Free parsed command list

## FuzzGen Generation Approach

### Step 1: Identify Target APIs

FuzzGen analyzes the codebase to identify entry points. For cmd-parse, the key APIs are:

```c
struct cmd_parse_result *cmd_parse_from_buffer(const char *, size_t, struct cmd_parse_input *);
struct cmd_parse_result *cmd_parse_from_string(const char *, struct cmd_parse_input *);
```

### Step 2: Data Provider Pattern

The harness uses a structured data provider to consume fuzz input systematically:

```c
struct data_provider {
    const uint8_t *data;
    size_t         size;
    size_t         pos;
};
```

Consumption functions:
- `dp_consume_byte()` - Single byte for flags/control
- `dp_consume_u16()` - 16-bit values for lengths
- `dp_consume_bytes()` - Byte arrays for payloads

### Step 3: Structured Input Layout

```
[flags_byte:1][payload_len:2][payload:N]
   └─ Bit 0: use_buffer vs use_string API
   └─ Bit 1: CMD_PARSE_VERBOSE flag
   └─ Bit 2: CMD_PARSE_PARSEONLY flag
   └─ Bit 3: CMD_PARSE_NOALIAS flag
   └─ Bit 4: Use filename context
   └─ Bit 5: Set line number
```

### Step 4: API Selection

Based on control byte bit 0:
- `0`: `cmd_parse_from_string()` - String-based parsing
- `1`: `cmd_parse_from_buffer()` - Buffer-based parsing

### Step 5: Flag Configuration

Parse flags derived from fuzz input:
```c
pi.flags = 0;
if (flags_byte & 0x02) pi.flags |= CMD_PARSE_VERBOSE;
if (flags_byte & 0x04) pi.flags |= CMD_PARSE_PARSEONLY;
if (flags_byte & 0x08) pi.flags |= CMD_PARSE_NOALIAS;
```

## Building

### LibFuzzer Build
```bash
clang -g -O1 -fsanitize=fuzzer,address \
    -I/path/to/tmux \
    cmd-parse-fuzzgen.c \
    /path/to/tmux/.libs/libtmux.a \
    -levent_core -lutil -lm -lresolv \
    -o cmd-parse-fuzzgen
```

### AFL++ Build
```bash
afl-clang-fast -g -O2 \
    -I/path/to/tmux \
    cmd-parse-fuzzgen.c afl-main.c tmux-stubs.c \
    /path/to/tmux/objs/*.o \
    -levent_core -lutil -lm -lresolv -lncurses \
    -o cmd-parse-fuzzgen-afl
```

## Running

### LibFuzzer
```bash
./cmd-parse-fuzzgen \
    corpus/cmd-parse/ \
    -max_len=4096 \
    -max_total_time=3600
```

### AFL++
```bash
afl-fuzz -i corpus/cmd-parse -o output/cmd-parse \
    -- ./cmd-parse-fuzzgen-afl
```

## Coverage Strategy

The FuzzGen approach explores:

1. **Both Parser APIs** - Toggles between buffer and string parsing
2. **All Flag Combinations** - Tests VERBOSE, PARSEONLY, NOALIAS
3. **Context Variations** - With/without filename and line info
4. **Payload Length Variations** - Variable-length command strings

## Expected Coverage Targets

- `cmd-parse.y` - Main YACC grammar
- `cmd.c` - Command table lookups
- `cmd-*.c` - Individual command handlers (when PARSEONLY=0)
- `arguments.c` - Argument parsing

## Comparison to Manual Harness

| Aspect | FuzzGen Style | Manual |
|--------|--------------|--------|
| Input Structure | Structured (header + payload) | Raw string |
| API Selection | Fuzz-controlled | Fixed |
| Flag Configuration | 6 dimensions | Fixed defaults |
| Complexity | Higher | Lower |
| Setup Overhead | ~4 bytes | 0 bytes |

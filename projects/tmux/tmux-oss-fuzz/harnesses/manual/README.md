# Manual Harnesses

This directory contains manually written fuzz harnesses for tmux. These represent what an experienced security researcher or developer would write as a one-shot harness for each target function.

## Design Philosophy

Manual harnesses are intentionally simple and direct:

1. **Fixed Configuration** - Uses standard/default values rather than deriving from fuzz input
2. **Direct API Calls** - Minimal wrapper code between fuzzer and target
3. **Clear Structure** - Easy to read, understand, and modify
4. **Proper Cleanup** - Ensures no resource leaks between iterations
5. **Minimal Overhead** - All bytes go directly to the target function

These harnesses serve as a **baseline** for comparing more sophisticated approaches (FuzzGen-style structured input, LLM-enhanced coverage hints).

## Harness Overview

| Harness | Target | Description |
|---------|--------|-------------|
| `input-fuzzer-manual.c` | `input_parse_buffer` | Terminal escape sequence parser |
| `cmd-parse-fuzzer.c` | `cmd_parse_from_buffer` | tmux command parser |
| `layout-parse-fuzzer.c` | `layout_parse` | Window layout string parser |
| `format-fuzzer.c` | `format_expand` | Format string expander |
| `style-fuzzer.c` | `style_parse` | Style attribute parser |
| `utf8-fuzzer.c` | `utf8_*` | UTF-8 validation and conversion |

## Harness Design Pattern

Each manual harness follows this structure:

```c
/*
 * [target]-fuzzer.c - Manual harness for tmux [functionality]
 *
 * Target: [file.c] ([target_function])
 * Description of what the target does and why it's a valuable fuzz target.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include "tmux.h"

#define FUZZER_MAXLEN [appropriate_size]

struct event_base *libevent;

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Bounds check */
    if (size == 0 || size > FUZZER_MAXLEN)
        return 0;

    /* Prepare input (null-terminate if needed) */
    char *input = malloc(size + 1);
    if (input == NULL)
        return 0;
    memcpy(input, data, size);
    input[size] = '\0';

    /* Setup (create required objects) */
    ...

    /* CORE TARGET CALL */
    target_function(input, ...);

    /* Cleanup */
    free(input);
    ...

    return 0;
}

int
LLVMFuzzerInitialize(__unused int *argc, __unused char ***argv)
{
    /* One-time global initialization */
    global_environ = environ_create();
    global_options = options_create(NULL);
    ...
    return 0;
}
```

## Individual Harness Details

### input-fuzzer-manual.c

**Target:** `input_parse_buffer()` in `input.c`

**Why it matters:** The input parser handles terminal escape sequences from PTYs. Bugs here could be exploited by malicious content displayed in tmux.

**Key features:**
- Fixed 80x25 pane dimensions (standard terminal size)
- Creates fresh window/pane each iteration
- Uses bufferevent pair for realistic I/O simulation
- Drains command queue after parsing
- Maximum input: 512 bytes (typical escape sequence limit)

### cmd-parse-fuzzer.c

**Target:** `cmd_parse_from_buffer()` in `cmd-parse.y`

**Why it matters:** Command parsing is the entry point for user input and configuration files. Command injection vulnerabilities would be critical.

**Key features:**
- Direct buffer parsing (no intermediate processing)
- Handles both success and error cases
- Maximum input: 4096 bytes (config line limit)

### layout-parse-fuzzer.c

**Target:** `layout_parse()` in `layout-custom.c`

**Why it matters:** Layout strings define pane arrangements. Malformed layouts could cause memory corruption in the layout tree.

**Key features:**
- Creates window with single pane for layout parsing
- Fixed 80x25 dimensions
- Handles error cause cleanup
- Maximum input: 2048 bytes

### format-fuzzer.c

**Target:** `format_expand()` in `format.c`

**Why it matters:** Format strings are used in status lines, hooks, and display. Complex nested expressions could trigger parser bugs.

**Key features:**
- Creates format tree with test variables
- Tests both `format_expand()` and `format_expand_time()`
- Fixed set of known variable values
- Maximum input: 2048 bytes

### style-fuzzer.c

**Target:** `style_parse()` in `style.c`

**Why it matters:** Style strings control colors and attributes. Parser bugs could cause crashes when processing malicious styles.

**Key features:**
- Tests with default grid cell
- Tests roundtrip via `style_tostring()`
- Tests with NULL base cell
- Maximum input: 1024 bytes

### utf8-fuzzer.c

**Target:** `utf8_*` functions in `utf8.c`

**Why it matters:** UTF-8 handling bugs can cause buffer overflows, invalid memory access, or incorrect rendering.

**Key features:**
- Tests multiple UTF-8 APIs
- Byte-by-byte parsing via `utf8_open()`/`utf8_append()`
- String validation via `utf8_isvalid()`
- Visualization via `utf8_strvis()`
- Maximum input: 1024 bytes

## Building

### LibFuzzer
```bash
clang -g -O1 -fsanitize=fuzzer,address \
    -I/path/to/tmux \
    input-fuzzer-manual.c \
    /path/to/tmux/.libs/libtmux.a \
    -levent_core -lutil -lm -lresolv \
    -o input-fuzzer
```

### AFL++
```bash
afl-clang-fast -g -O2 \
    -I/path/to/tmux \
    input-fuzzer-manual.c afl-main.c tmux-stubs.c \
    /path/to/tmux/objs/*.o \
    -levent_core -lutil -lm -lresolv -lncurses \
    -o input-fuzzer-afl
```

## Running

```bash
# LibFuzzer
./input-fuzzer corpus/input-parse/ -max_len=512 -max_total_time=3600

# AFL++
afl-fuzz -i corpus/input-parse -o output/input-parse -- ./input-fuzzer-afl
```

## Comparison Philosophy

Manual harnesses provide:
- **Simplicity**: Easy to audit, understand, and modify
- **Directness**: Minimal code between fuzzer and target
- **Baseline**: Reference for comparing LLM and FuzzGen approaches

Tradeoffs vs. other approaches:
- **vs FuzzGen**: Less configuration coverage, but no setup overhead
- **vs LLM**: No coverage hints, but cleaner code paths

---

## Coverage Results

### `input-fuzzer-manual.c` (60s run)

| Metric | Coverage |
|--------|----------|
| Lines | 74.28% |
| Regions | 69.34% |
| Functions | 76.92% |
| Branches | 72.22% |

See main harnesses README for full comparison data.

**Both miss (18 functions — expected):**

These fall into two categories neither harness can reach with the current design:

1. **Async request/timer infrastructure** — `input_make_request`, `input_free_request`, `input_start_request_timer`, `input_ground_timer_callback`, `input_request_timer_callback`, `input_handle_decrqss`, `input_osc_133`, `input_request_clipboard_reply`, `input_request_palette_reply`, `input_report_current_theme`. These require a live client responding to server-side OSC/DCS queries, which is out-of-scope for a single-component harness.

2. **Alternative entry points** — `input_parse_pane`, `input_parse_screen`, `input_pending`, `input_cancel_requests`, `input_request_reply`, `input_reply_clipboard`, `input_set_buffer_size`. These are wrappers or utilities that require a session/client context or are not reachable through `input_parse_buffer` alone. A separate harness would be needed to push function coverage above ~80%.

---
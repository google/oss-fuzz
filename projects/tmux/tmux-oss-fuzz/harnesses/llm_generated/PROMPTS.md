# LLM Harness Generation: Prompts & Strategies

## Overview

LLM-generated harnesses were created using a structured prompting approach targeting
six tmux parsing/processing surfaces. Each harness was iteratively refined based on
build failures, crash analysis, and coverage gaps.

## General Prompting Strategy

### Phase 1: Initial Generation

**Prompt template:**
```
You are an expert in fuzzing and security testing. Generate a libFuzzer harness
for the tmux function `{TARGET_FUNCTION}` defined in `{SOURCE_FILE}`.

Requirements:
- Include proper LLVMFuzzerInitialize() that sets up tmux global state
  (global_environ, global_options, global_s_options, global_w_options, libevent)
- Include LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
- Use coverage_hint() calls to guide the fuzzer toward interesting paths
- Handle memory cleanup to avoid false-positive leak reports
- Limit input size to prevent OOM (max 1024-8192 bytes)
- Include structural analysis of the input for coverage signals
- The harness must compile with: clang -fsanitize=fuzzer,address
- Link against tmux object files and libevent

Global initialization pattern (REQUIRED):
  global_environ = environ_create();
  global_options = options_create(NULL);
  global_s_options = options_create(NULL);
  global_w_options = options_create(NULL);
  for (oe = options_table; oe->name != NULL; oe++) { ... options_default ... }
  libevent = osdep_event_init();
  socket_path = xstrdup("dummy");

Here is the source code of the target function:
{SOURCE_CODE}

Here is the tmux.h header with relevant declarations:
{HEADER_EXCERPT}
```

### Phase 2: Coverage-Guided Refinement

After initial generation, harnesses were refined with:

```
The harness achieves {X}% coverage. Analyze the target function and add test
cases that exercise:
1. Edge cases in input parsing (empty, max-size, boundary values)
2. Error handling paths (malformed input, invalid state)
3. Different operation modes selected by input bytes
4. Nested/recursive structures
5. Add coverage_hint() annotations to track which paths are hit
```

### Phase 3: Bug-Fix Iteration

When harnesses crashed during testing:

```
The harness crashes with {ERROR_TYPE} at {LOCATION}. Here is the ASAN output:
{ASAN_TRACE}

Fix the harness to avoid this crash while still exercising the same code paths.
Common fixes:
- Missing global state initialization
- Memory leaks from not freeing parse results
- Unbounded input size causing OOM
- Null pointer dereference from missing setup
```

## Per-Target Strategies

### input-parse-llm.c
- **Target:** `input_parse_buffer()` in input.c
- **Strategy:** Use first byte as config selector to toggle terminal modes
  (bracketed paste, cursor keys, application keypad)
- **Key insight:** Creating a `struct window_pane` with proper `input_init()`
  gives the most realistic coverage
- **Result:** Best-performing LLM harness (9.57% line coverage, 352K execs)

### cmd-parse-llm.c
- **Target:** `cmd_parse_from_string()` and `cmd_parse_from_buffer()` in cmd-parse.y
- **Strategy:** Custom mutator with tmux command dictionary for structure-aware
  fuzzing. First byte selects between string and buffer parse surfaces.
- **Key insight:** Custom mutator with command tokens (new-session, bind-key, etc.)
  helps reach deeper parser states
- **Refinement:** Added max input size (8192 bytes) to prevent OOM from parser
  memory accumulation over millions of iterations
- **Result:** 4.6M executions, OOM fixed with size limit

### layout-parse-llm.c
- **Target:** `layout_parse()` in layout-custom.c
- **Strategy:** Layout string structure awareness (checksums, dimensions, nesting)
- **Key insight:** tmux layout format is `CHECKSUM,WxH,Px,Py[{CHILD,...}]` -
  including a checksum calculator helps generate valid-looking inputs
- **Refinement:** Reduced from 3 window_create() per iteration to 1 with
  resize-based testing to avoid OOM from window object accumulation
- **Result:** Fixed OOM, maintained coverage across different window sizes

### utf8-llm.c
- **Target:** `utf8_open()`, `utf8_append()`, `utf8_isvalid()`, `utf8_strvis()` etc.
- **Strategy:** UTF-8 byte sequence awareness covering 1-4 byte sequences,
  overlong encodings, surrogate pairs, BOM, zero-width characters
- **Key insight:** Must initialize global_options BEFORE calling
  `utf8_update_width_cache()` - the function calls
  `options_get(global_options, "codepoint-widths")` internally
- **Critical fix:** Added full option tree initialization in LLVMFuzzerInitialize()
  (was previously causing immediate SEGV)
- **Result:** After fix, exercises 13 distinct UTF-8 test paths

### format-llm.c
- **Target:** `format_expand()` in format.c
- **Strategy:** Format string structure with tmux format variables (#{...}),
  style tags (#[...]), conditionals (#{?...,...,...})
- **Key insight:** format_expand() is deeply recursive and touches many tmux
  internals. The harness correctly found a real heap-buffer-overflow bug.
- **Result:** Finds real bugs quickly (12.5K execs to first crash)

### style-llm.c
- **Target:** `style_parse()` in style.c
- **Strategy:** Style attribute combinations (fg/bg colors, bold, dim, etc.)
  with structural analysis of the style string
- **Key insight:** style_parse is relatively self-contained - minimal setup needed
- **Result:** Highest throughput (54,857 exec/s, 16.5M executions, no crashes)

## Common Patterns

### Coverage Hints
All harnesses use `coverage_hint(int id)` - a noinline function that writes to
a volatile variable. This helps libFuzzer's value profiling distinguish code paths:
```c
static void __attribute__((noinline))
coverage_hint(int path_id) {
    volatile int x = path_id;
    (void)x;
}
```

### Input Slicing
Use first byte(s) as mode selectors to explore different code paths:
```c
uint8_t mode = data[0];
const uint8_t *payload = data + 1;
size_t plen = size - 1;
```

### Required Global Initialization
Every harness that touches tmux internals must initialize:
1. `global_environ` via `environ_create()`
2. Options trees (`global_options`, `global_s_options`, `global_w_options`)
3. Default options via `options_default()` loop
4. `libevent` via `osdep_event_init()`
5. `socket_path` via `xstrdup()`

### Structural Analysis
Pre-analyze input structure before calling target functions to provide
coverage signals (nest depth, special characters, format markers, etc.)

## Lessons Learned

1. **Always initialize global state** - tmux functions assume globals are set up.
   Missing initialization causes immediate SEGV.
2. **Limit input size** - Parser functions can allocate memory proportional to
   input size. Cap at 2048-8192 bytes to prevent OOM.
3. **Minimize per-iteration allocations** - Creating complex objects (windows,
   panes) every iteration causes memory growth. Reuse objects when possible.
4. **Custom mutators help** - Structure-aware mutation (cmd tokens, format
   strings) reaches deeper parser states faster.
5. **Real bugs emerge quickly** - format-llm.c found a heap-buffer-overflow
   in just 12,596 iterations.
6. **Disable leak detection** - Use `-detect_leaks=0` since tmux has
   intentional one-time allocations that ASAN reports as leaks.

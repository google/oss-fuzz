# FuzzGen-Style Harnesses

This directory contains harnesses following the FuzzGen approach of structured input consumption, similar to the FuzzedDataProvider pattern in libFuzzer.

## Generation Methodology

These harnesses were created by manually implementing the FuzzGen methodology, which involves:

### 1. API Analysis

For each target, we identified:
- Entry point functions
- Configuration parameters
- State requirements
- Cleanup procedures

### 2. Data Provider Implementation

All harnesses use a consistent data provider pattern:

```c
struct data_provider {
    const uint8_t *data;
    size_t         size;
    size_t         pos;
};

static uint8_t dp_consume_byte(struct data_provider *dp);
static uint16_t dp_consume_u16(struct data_provider *dp);
static size_t dp_remaining(struct data_provider *dp);
static const uint8_t *dp_consume_bytes(struct data_provider *dp, size_t count);
```

### 3. Structured Input Design

Each harness defines a header format that controls:
- API selection (which function to test)
- Configuration flags
- Object parameters (dimensions, colors, etc.)
- Remaining bytes as payload

## Contents

| File | Target | Documentation |
|------|--------|---------------|
| `input-fuzzer-fuzzgen.c` | input.c | [README-input-fuzzer-fuzzgen.md](README-input-fuzzer-fuzzgen.md) |
| `cmd-parse-fuzzgen.c` | cmd-parse.y | [README-cmd-parse-fuzzgen.md](README-cmd-parse-fuzzgen.md) |
| `layout-parse-fuzzgen.c` | layout-custom.c | [README-layout-parse-fuzzgen.md](README-layout-parse-fuzzgen.md) |
| `utf8-fuzzgen.c` | utf8.c | [README-utf8-fuzzgen.md](README-utf8-fuzzgen.md) |
| `format-fuzzgen.c` | format.c | [README-format-fuzzgen.md](README-format-fuzzgen.md) |
| `style-fuzzgen.c` | style.c | [README-style-fuzzgen.md](README-style-fuzzgen.md) |

## FuzzGen Approach

These harnesses use structured data consumption where the first bytes of fuzz input control test configuration.

### Key Principles

1. **Structured Input Consumption**
   - First N bytes: Control bytes (API selection, flags, parameters)
   - Remaining bytes: Payload data

2. **API Exploration**
   - Control byte selects which API to test
   - Enables coverage of multiple entry points

3. **Configuration Coverage**
   - Parameters derived from fuzz input
   - Tests edge cases in configuration

4. **Reproducibility**
   - All configuration encoded in input
   - Seeds are self-describing

### Example: Input Parser

```
Fuzz Input Layout:
[width:4][height:4][flags:1][allow_rename:1][set_clipboard:5][escape_data:N]

Consumption:
1. Consume width (uint32, range 10-200)
2. Consume height (uint32, range 5-100)
3. Consume flags (byte, lower 4 bits)
4. Consume allow_rename (bool)
5. Consume set_clipboard (bool + uint32 if true)
6. Remaining bytes → escape sequences
```

### Example: Command Parser

```
Fuzz Input Layout:
[flags_byte:1][payload_len:2][payload:N]

Consumption:
1. Bit 0: Use buffer vs string API
2. Bit 1-4: Parse flags (VERBOSE, PARSEONLY, NOALIAS, etc.)
3. Bits 5-7: Context configuration
4. U16: Payload length
5. Remaining: Command string
```

## Building

### LibFuzzer Build (All Harnesses)

```bash
cd /path/to/tmux
for harness in cmd-parse format input-fuzzer layout-parse style utf8; do
    clang -g -O1 -fsanitize=fuzzer,address \
        -I. \
        harnesses/fuzzgen_generated/${harness}-fuzzgen.c \
        .libs/libtmux.a \
        -levent_core -lutil -lm -lresolv \
        -o build/${harness}-fuzzgen
done
```

### AFL++ Build

```bash
for harness in cmd-parse format input-fuzzer layout-parse style utf8; do
    afl-clang-fast -g -O2 \
        -I/path/to/tmux \
        ${harness}-fuzzgen.c ../afl-main.c ../tmux-stubs.c \
        /path/to/tmux/objs/*.o \
        -levent_core -lutil -lm -lresolv -lncurses \
        -o build/afl/${harness}-fuzzgen
done
```

## Running

### LibFuzzer
```bash
./build/input-fuzzer-fuzzgen \
    corpus/input-parse/ \
    -max_len=512 \
    -max_total_time=3600
```

### AFL++
```bash
afl-fuzz -i corpus/input-parse -o output/input-parse \
    -- ./build/afl/input-fuzzer-fuzzgen
```

## Comparing Harness Types

### Expected Characteristics

| Aspect | FuzzGen | Manual | LLM |
|--------|---------|--------|-----|
| Input Structure | Header + Payload | Raw | Raw |
| Configuration | Fuzz-controlled | Fixed | Fixed |
| API Coverage | Multiple per harness | Single target | Single + hints |
| Setup Overhead | 2-15 bytes | 0 | 0 |
| Edge Cases | Configuration-based | Data-based | Hint-guided |

### Coverage Comparison

```bash
./scripts/compare_coverage.sh
```

## Why FuzzGen Style?

1. **Configuration Coverage** - Tests parameter edge cases
2. **API Exploration** - Single harness covers multiple entry points
3. **Reproducibility** - Full test case in single input
4. **Structure-Aware** - Generates syntactically valid inputs

## Limitations

1. **Setup Overhead** - Control bytes reduce payload
2. **Complexity** - More complex harness code
3. **Corpus Compatibility** - Different format than manual harnesses

The harness in this directory is a hand-crafted FuzzGen-style harness. To generate with actual FuzzGen:

1. Install LLVM 6
2. Build FuzzGen
3. Generate LLVM IR for tmux
4. Run FuzzGen analysis

See [automated-harness-generation.md](../../docs/automated-harness-generation.md) for details.

## Contributing New Harnesses

To add new generated harnesses:

1. Create the harness in this directory
2. Document the generation method
3. Add build instructions
4. Test locally
5. Submit a PR

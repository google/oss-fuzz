# LLM-Generated Harnesses

This directory contains fuzzing harnesses enhanced with LLM-designed optimizations for improved coverage exploration.

## Generation Prompts

The following prompts were used to generate and improve these harnesses:

### Base Prompt Template

```
Create a libFuzzer harness for tmux's [TARGET] functionality.

Target Functions:
- [FUNCTION_LIST]

Requirements:
1. Standard LLVMFuzzerTestOneInput and LLVMFuzzerInitialize
2. Use coverage_hint() calls to guide the fuzzer toward interesting paths
3. Analyze input structure to classify patterns
4. Test multiple APIs/code paths
5. Include proper cleanup and memory safety

Coverage Optimization Strategy:
- Add noinline coverage_hint(int path_id) function
- Call coverage_hint with unique IDs for distinct code paths
- Detect input patterns that trigger specific functionality
- Use dictionary awareness for known valid tokens
```

### format-llm.c Generation Prompt

```
Create a coverage-optimized libFuzzer harness for tmux format string expansion.

Target: format.c

Key patterns to detect:
- Format placeholders: #{...}, #(...), #[...]
- Conditional expressions: #{?cond,true,false}
- Comparisons: #{==:a,b}, #{!=:a,b}, #{<:a,b}, #{>:a,b}
- Format modifiers: #{=width:var}, #{:s/old/new:var}
- Time specifiers: %Y, %m, %d, %H, %M, %S

Test variations:
1. format_expand() with different FORMAT_* flags
2. format_expand_time() for time formatting
3. Test with known variable names populated
4. Test nested conditionals with real variable values
5. Test format modifiers (padding, substitution)

Add coverage hints for:
- Each placeholder type detected
- Nested structure depth
- Conditional vs non-conditional paths
- Known vs unknown variable names
- Time specifier presence
```

### layout-parse-llm.c Generation Prompt

```
Create a coverage-optimized libFuzzer harness for tmux layout parsing.

Target: layout-custom.c (layout_parse)

Layout format: CHECKSUM,WxH,X,Y[{CHILDREN}]
Example: "b3e7,80x24,0,0{40x24,0,0,0,39x24,41,0,1}"

Key patterns to detect:
- Valid checksum presence
- Dimension specifications (WxH)
- Nesting with {} and []
- Comma separators

Test variations:
1. Parse with standard 80x25 window
2. Parse with smaller window (40x12) - tests minimum handling
3. Parse with larger window (160x48) - tests scaling
4. Parse with minimal window (10x3) - tests boundary
5. After successful parse, test layout_fix_panes()
6. Test layout_resize() in both directions
7. Test layout_spread_out()

Add coverage hints for:
- Checksum detection
- Dimension parsing
- Nesting depth (1-3+ levels)
- Parse success vs failure
- Different window sizes
```

### style-llm.c Generation Prompt

```
Create a coverage-optimized libFuzzer harness for tmux style parsing.

Target: style.c (style_parse, style_tostring)

Style format: comma-separated attributes
Examples: "fg=red,bg=blue,bold", "align=centre,list=on"

Key patterns to detect:
- Color formats: named, RGB (#RRGGBB), 256-color (colour0-255)
- Attributes: bold, dim, underscore, blink, reverse, hidden
- Special attributes: curly-underscore, dotted-underscore, overline, strikethrough
- Range/list: range=left|right|window|user, list=on|focus|markers
- Alignment: align=left|centre|right|absolute-centre
- Default control: push-default, pop-default

Test variations:
1. Parse with default grid cell
2. Parse with custom fg/bg colors  
3. Test style_tostring roundtrip
4. Test with 256-color base cells
5. Test RGB color handling
6. Test underscore style variants
7. Test fill attribute
8. Test push-default/pop-default

Add coverage hints for:
- Each attribute type detected
- Color format types
- Roundtrip success
- Multiple styles (comma-separated)
- Special underscore variants
```

### utf8-llm.c Generation Prompt

```
Create a coverage-optimized libFuzzer harness for tmux UTF-8 handling.

Target: utf8.c (utf8_open, utf8_append, utf8_isvalid, utf8_strvis)

UTF-8 patterns:
- ASCII: 0x00-0x7F
- 2-byte: 0xC0-0xDF + continuation
- 3-byte: 0xE0-0xEF + 2 continuations
- 4-byte: 0xF0-0xF7 + 3 continuations
- Invalid: overlong encodings, surrogates, truncated sequences

Test variations:
1. utf8_isvalid() - whole string validation
2. utf8_strvis() - with VIS_OCTAL, VIS_CSTYLE, VIS_TAB, VIS_NL
3. utf8_open/utf8_append cycle - byte-by-byte parsing
4. utf8_towc() - wchar conversion with width checking
5. utf8_from_data/utf8_to_data roundtrip
6. utf8_build_one() - single byte chars
7. Multiple complete sequences processing

Add coverage hints for:
- Byte type classification (lead byte types)
- Overlong encoding detection
- Surrogate pair detection
- Valid vs invalid UTF-8
- Character width (0, 1, 2, invalid)
- BOM detection (EF BB BF)
- Zero-width characters
- Combining characters
```

## Key Features

### Coverage Hints

Each harness includes strategic `coverage_hint()` calls that:
- Force distinct code paths based on input characteristics
- Guide the fuzzer toward interesting input patterns
- Create observable differences for coverage-guided mutation

### Input Classification

Harnesses analyze input structure to identify:
- **format-llm.c**: Format placeholders, conditionals, modifiers, time specs
- **layout-parse-llm.c**: Checksum, dimensions, nesting, parse success
- **style-llm.c**: Color formats, attributes, range/list, underscore variants
- **utf8-llm.c**: Byte patterns, overlong, surrogates, special chars

### Dictionary Awareness

Known valid patterns are checked to enable smart mutation:
- tmux command names
- Format variable names
- Style attribute keywords
- Color names

## Example: Coverage Hint Pattern

```c
static void __attribute__((noinline))
coverage_hint(int path_id)
{
    volatile int x = path_id;
    (void)x;
}

// In LLVMFuzzerTestOneInput:
if (data[0] == '\x1b' && data[1] == '[') {
    coverage_hint(1);  // CSI sequence path
} else if (data[0] == '\x1b' && data[1] == ']') {
    coverage_hint(2);  // OSC sequence path
}
```

The `noinline` attribute ensures the fuzzer sees these as distinct code paths.

## Files

| File | Target | Key Optimizations |
|------|--------|-------------------|
| input-parse-llm.c | input.c | Escape sequence classification, state machine hints |
| cmd-parse-llm.c | cmd-parse.y | Command prefix detection, syntax element tracking |
| layout-parse-llm.c | layout-custom.c | Checksum calculation, nesting depth tracking |
| utf8-llm.c | utf8.c | UTF-8 pattern detection, validity checking |
| format-llm.c | format.c | Placeholder detection, conditional expression tracking |
| style-llm.c | style.c | Style attribute awareness, color format detection |

## Expected Benefits

1. **Faster coverage growth** due to guided exploration
2. **Better edge case discovery** through pattern-aware mutation
3. **More efficient corpus generation** by preferring structured inputs

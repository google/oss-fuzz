---
name: fuzzing-memory-unsafe-expert
description:
  Use this skill to fuzz open source C/C++ software projects.
---

# Fuzzing memory-unsafe expert

This skill provides the agent with the necessary knowledge and tools to fuzz open source software projects, particularly those that are part of the OSS-Fuzz program. The agent can use this skill to build fuzzers, run fuzzing campaigns, analyze results, and improve the fuzzing posture of projects.

The fuzzing abilities focused on here is libFuzzer-style harnesses, which are commonly used in OSS-Fuzz.

## Threat modelling and attack surface

Before writing a single line of harness code, decide **what you are trying to
find and where an attacker's input actually enters the code**. A harness is
only as good as the entry point it targets: a technically-correct harness
pointed at code no attacker can influence finds bugs no maintainer will fix.
This step is what separates a valuable harness from a noisy one.

### What a threat model answers

For the target project, answer these four questions explicitly and write the
answers into the harness's rationale doc:

1. **What input is untrusted?** The data an attacker can control — a file
   downloaded and opened, bytes arriving on a socket, a message from another
   process, a document pasted into an editor. Trusted input (a config file the
   admin wrote, a compile-time constant, a path only the program itself
   constructs) is *not* an attacker's lever and is usually out of scope.
2. **Where does that input cross a trust boundary?** The exact function(s)
   where untrusted bytes first reach parsing/processing logic. This is the
   entry point your harness should call.
3. **What does the attacker control at that boundary?** The whole buffer? Only
   a length field, with the rest validated upstream? A filename but not its
   contents? This determines what your harness should mutate and what it should
   hold fixed.
4. **What would count as a real bug here?** A memory-safety violation (ASan/
   MSan/UBSan finding) on attacker-reachable input is almost always in scope. A
   crash that requires trusted/malformed *developer* input, or an
   `assert()`-guarded programmer-error precondition, usually is not — fuzzing it
   produces findings maintainers reject.

### Identifying the attack surface

Concrete, common attack surfaces in C/C++ projects, and the entry points to
target for each:

- **File-format parsers / loaders** (image, audio, video, fonts, archives,
  documents). Entry point: the function that takes a buffer or file and decodes
  it — e.g. `png_read_info`, `TIFFClientOpen`, `av_read_frame`,
  `archive_read_open_memory`. Attacker controls the whole file. High-value,
  classic OSS-Fuzz target.
- **Network / wire-protocol handlers** (packet parsers, TLS records, HTTP,
  DNS, RPC deserialisation). Entry point: the function fed raw bytes off the
  wire, e.g. `SSL_read`, `parse_packet`, `deserialize_message`. Attacker
  controls the byte stream; often you must also drive a state machine (see the
  reachability note below).
- **Serialisation / IPC boundaries** (protobuf/JSON/CBOR/ASN.1 decoders,
  shared-memory messages, clipboard, environment when spawned by another
  privilege domain). Entry point: the *decode* direction — the untrusted side
  is bytes-in, not object-out.
- **Text / query languages** (SQL, regex, template engines, config-language
  parsers, expression evaluators). Entry point: the compile/parse function that
  accepts an arbitrary string.
- **Decompression and codecs** (zlib, lz4, zstd, JPEG/HEIF bitstreams). Entry
  point: the decompress/decode call on attacker-supplied compressed data —
  these are prime targets because a small input expands into large, structured
  work.

### Deriving the harness from the threat model

The threat model dictates the harness shape:

- **Target the untrusted-input direction only.** Fuzz the *decoder*, not the
  encoder; the *reader*, not the writer — unless the writer also consumes
  attacker-controlled data.
- **Mutate exactly what the attacker controls; fix the rest.** If the attacker
  controls a document but not the parser's configuration, mutate the document
  bytes and hold the config constant (set it once in `LLVMFuzzerInitialize`).
  Fuzzing the config too invents a threat that does not exist and yields
  rejected findings.
- **Enter at the real trust boundary, not below it.** Calling a deep internal
  helper directly may crash on inputs the public API would have rejected
  upstream — a false positive. Prefer the outermost function an attacker's data
  actually reaches. If you must call an internal function for coverage, first
  confirm the upstream validation it assumes, and reproduce that precondition
  in the harness.
- **Honour the API contract to avoid false positives.** If a function is
  documented to require NUL-terminated input, a valid handle, or a
  pre-allocated output buffer, supply those — a crash from violating the
  contract is a harness bug, not a target bug (this is the "True Positives"
  characteristic below).

### Reachability: entry point is not enough

An entry point that is untrusted-reachable in production may still be
*unreachable* from your harness if getting to the interesting code requires
state the harness never sets up — an open session, a completed handshake, a
prior header packet, a registered codec. Two consequences:

- If the deep code needs prior state, **build that state in the harness**
  (e.g. feed a valid header, complete the handshake) before feeding the mutated
  bytes — otherwise the fuzzer never gets past the front door and coverage
  stays shallow.
- Cross-check with the coverage data (see the OSS-Fuzz engineer skill): if a
  file you believe is attacker-reachable sits dark in `summary.json`, decide
  whether it is *seed-limited* (a better corpus would reach it — write seeds) or
  *harness-limited* (no input reaches it as the harness stands — the harness
  itself must set up more state).

### A worked example

Consider a library that loads a custom image format via
`int img_load(const uint8_t *buf, size_t len, img_opts *opts)`, where `opts`
comes from the application, not the file:

- **Untrusted input:** `buf`/`len` (the image file). **Trusted:** `opts`.
- **Trust boundary / entry point:** `img_load` — the outermost public function
  an attacker's bytes reach.
- **Attacker controls:** the entire image buffer, not the options.
- **Real bug:** any ASan/UBSan finding decoding a crafted image.

The harness therefore fixes `opts` to a representative default once, and feeds
the mutated bytes as `buf`/`len`:

```cpp
#include <fuzzer/FuzzedDataProvider.h>

static img_opts g_opts;  // trusted config, set once — not fuzzed.

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
    img_opts_default(&g_opts);   // represents the real application's setup
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Attacker controls the whole file; feed it directly.
    img_load(data, size, &g_opts);
    return 0;
}
```

Fuzzing `opts` instead, or calling an internal `decode_scanline` directly with
raw bytes, would either invent a non-existent threat or trip asserts the public
API prevents — both produce findings maintainers will not act on.

## Fundamental Concepts

### Fuzzing harness core function

A fuzzing harness is a function that takes a byte array as input and processes it in a way that can trigger bugs or vulnerabilities in the software being tested. The core function of a fuzzing harness typically looks like this:

```cpp
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Process the input data and trigger potential bugs
    return 0; // Return 0 to indicate successful processing
}
```

Return `0` in all normal cases. Return `-1` to tell libFuzzer to reject an
input and not add it to the corpus (rarely needed). Never `exit()` on bad
input — it aborts the whole run and breaks coverage tooling.

### Extracting typed input with FuzzedDataProvider

Most non-trivial targets do not take a single flat byte buffer — they need an
integer here, a length there, a string, several sub-buffers. Passing the raw
`data`/`size` directly to such an API means the fuzzer almost never produces a
well-formed call. `FuzzedDataProvider` splits the one input stream into typed
values, so libFuzzer's mutations map onto the parameters the target actually
expects. It is the standard tool for this in OSS-Fuzz (used by well over a
hundred projects) and is shipped in the base image — no dependency to add:

```cpp
#include <fuzzer/FuzzedDataProvider.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);

    // Consume typed, bounded values up front...
    int         width  = fdp.ConsumeIntegralInRange<int>(1, 4096);
    bool        strict = fdp.ConsumeBool();
    std::string name   = fdp.ConsumeRandomLengthString(64);
    // ...then hand the rest of the bytes to the payload argument.
    std::vector<uint8_t> payload = fdp.ConsumeRemainingBytes<uint8_t>();

    my_decode(name.c_str(), width, strict, payload.data(), payload.size());
    return 0;
}
```

Commonly used methods (see `compiler-rt`'s `FuzzedDataProvider.h` for the full
set):

| Method | Description |
|---|---|
| `ConsumeIntegral<T>()` | one integer of type `T` |
| `ConsumeIntegralInRange<T>(min, max)` | integer bounded to `[min, max]` — use this to pick sizes, indices, enum values |
| `ConsumeBool()` | one boolean |
| `ConsumeEnum<E>()` | a value of a scoped enum with `kMaxValue` |
| `ConsumeFloatingPoint<T>()` / `...InRange(min, max)` | float/double |
| `ConsumeRandomLengthString(max)` | a `std::string` whose length the fuzzer controls (stops at an escaped `\`) |
| `ConsumeBytes<T>(count)` / `ConsumeBytesAsString(count)` | exactly `count` bytes |
| `ConsumeRemainingBytes<T>()` / `ConsumeRemainingBytesAsString()` | everything left |
| `remaining_bytes()` | how many bytes are left to consume |

Guidance:

- **Consume in a fixed order and document it.** The mapping from bytes to
  parameters must be stable, or a saved crash will not reproduce.
- **Consume the variable-length / "rest of the input" argument last** with
  `ConsumeRemaining...`. Consuming a fixed count first and the remainder last
  keeps the layout robust to mutation.
- **Bound sizes and indices with `ConsumeIntegralInRange`** rather than masking
  a raw integer — it wastes fewer inputs and keeps allocations sane.
- Use FDP when the target needs structure; for a target that genuinely takes
  one opaque buffer (a single `parse(data, size)`), pass `data`/`size` straight
  through — FDP would only add noise.

### One-time setup with LLVMFuzzerInitialize

If the harness needs setup that must happen once before fuzzing (parsing
`argv`, setting environment variables, initialising a library global), put it
in the optional `LLVMFuzzerInitialize` hook, which libFuzzer calls once at
startup — never do per-input work there:

```cpp
extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
    setenv("HOME", "/tmp", 1);
    my_library_global_init();
    return 0;
}
```

Keep expensive but per-process-constant state (loaded config, a compiled
schema, an allocated context reused across inputs) in a file-scope
`static`/global initialised once — either here or lazily on the first
`LLVMFuzzerTestOneInput` call — so it is not rebuilt on every iteration.

### Sanitizers are the bug oracle

A C/C++ harness rarely detects a bug by itself — the sanitizer the project is
built with is what turns silent memory corruption into a crash the fuzzer can
catch. OSS-Fuzz builds each target under a sanitizer (default AddressSanitizer;
also UndefinedBehaviorSanitizer and MemorySanitizer):

- **ASan** — heap/stack/global buffer overflows, use-after-free, double-free,
  leaks. The default and highest-value oracle.
- **UBSan** — signed overflow, invalid shifts, misaligned/`null` pointer use,
  bad casts, invalid enum values.
- **MSan** — reads of uninitialised memory. Requires *all* linked code
  (including dependencies) to be instrumented, or it reports false positives —
  only enable it when the whole dependency chain is built under MSan.

Design implication: the harness's job is to *reach* untrusted-input-driven
memory operations with enough variety; the sanitizer reports the violation.
`build.sh` must compile both the target library and the harness with the
OSS-Fuzz `$CFLAGS`/`$CXXFLAGS` (which carry the sanitizer + coverage flags) —
linking against a separately, non-instrumented build silently disables the
oracle and coverage guidance.

### Building in OSS-Fuzz

`build.sh` compiles the project (as a static library where possible) and then
compiles + links each harness against it with `$LIB_FUZZING_ENGINE`. Always use
the OSS-Fuzz-provided `$CC`/`$CXX` and `$CFLAGS`/`$CXXFLAGS` so instrumentation
and the sanitizer are applied:

```bash
# build.sh — build the library with instrumentation, statically.
mkdir build && cd build
cmake -DBUILD_SHARED_LIBS=OFF ..     # a static .a is easiest to link the harness against
make -j$(nproc)
cd ..

# Compile and link each harness against the instrumented library.
for f in $SRC/project/fuzz/*_fuzzer.cc; do
    fuzzer=$(basename "$f" _fuzzer.cc)
    $CXX $CXXFLAGS -std=c++17 -I$SRC/project/include \
        "$f" -o "$OUT/${fuzzer}" \
        $LIB_FUZZING_ENGINE "$SRC/project/build/libproject.a"
done
```

Key points:

- Link the harness with **`$LIB_FUZZING_ENGINE`**, not a hardcoded
  `-fsanitize=fuzzer` — this lets OSS-Fuzz swap the engine (libFuzzer, AFL++,
  Centipede, or the coverage/`check_build` no-op engine).
- Prefer a **static** project build; it avoids `LD_LIBRARY_PATH` juggling at
  run time and ensures the linked code is instrumented.
- Copy seed corpora (`$OUT/<fuzzer>_seed_corpus.zip`) and dictionaries
  (`$OUT/<fuzzer>.dict`) in the same script.

### Examples of good harnesses already in OSS-Fuzz

Study existing harnesses before writing your own — they show the idioms above
applied to real projects, and matching an established style makes your harness
easier for maintainers to accept. Each example below is checked into this
repository; open the file and read it in full.

- **`projects/sentencepiece/sample_encode_fuzzer.cc`** — the canonical
  `FuzzedDataProvider` split. It carves the one input into an `int`
  (`ConsumeIntegral`), a `float` (`ConsumeFloatingPoint`) and the remaining
  bytes as the text argument (`ConsumeRemainingBytesAsString`), then calls
  `SampleEncodeAsSerializedProto(text, nbest, alpha)`. Note the ordering: the
  fixed-size scalars are consumed first and the variable-length string last.
  This is the template whenever the target API takes several typed parameters
  rather than one buffer.

- **`projects/spdlog/fuzz/pattern_fuzzer.cc`** — lazy one-time initialisation
  and a tightly-scoped threat model. A `static` logger is created on the first
  call and reused across iterations (never rebuilt per input), it guards
  `size == 0`, and it fuzzes exactly one attacker-relevant entry point:
  `spdlog::set_pattern(str)`, the format-pattern parser. It does *not* fuzz the
  logging config — a clean example of "mutate only what the attacker controls."

- **`projects/file/magic_fuzzer_fd.cc`** — `LLVMFuzzerInitialize` for expensive
  setup, and feeding an API that needs a real file descriptor. The magic
  database is loaded once in an `Environment` built from `argv[0]`'s directory
  (setup that must not repeat per input), and each input is written to a
  `FuzzerTemporaryFile` so it can be handed to `magic_descriptor(fd)`. Use this
  pattern when the target only accepts a path/`fd` rather than an in-memory
  buffer — but note that going through a temp file is slower, so prefer an
  in-memory entry point when the library exposes one.

When extending an existing OSS-Fuzz project, the best reference is that
project's *own* existing harnesses: match their file layout, naming
(`*_fuzzer.cc`), build-script wiring and error-handling conventions.

### Characteristics found in good fuzzing harnesses

The below are characteristics commonly found in good fuzzing harnesses, which contribute to their effectiveness in finding bugs. They are not all necessary for a good harness and at times it may even be desirable to actively not pursue some of them.

1. **Simplicity**: The harness should be simple and focused on processing the input data without unnecessary complexity.
2. **Coverage**: The harness should aim to cover as much of the codebase as possible, including edge cases and error handling paths.
3. **Determinism**: The harness should produce consistent results for the same input, allowing for reliable reproduction of bugs.
4. **Performance**: The harness should be efficient in processing inputs to maximize the number of test cases that can be executed in a given time frame.
5. **Error Handling**: The harness should include robust error handling to capture and report any issues that arise during fuzzing.
6. **True Positives**: The harness should be designed to have no false positives, ensuring that reported issues are genuine bugs. This means all issues found by the fuzzer is something the maintainers are interested in fixing.
7. **Matches threat model**: The harness should be designed to target specific types of vulnerabilities that are relevant to the project being fuzzed.
8. **Hits code on the attack surface**: The harness should be designed to target code that is exposed to untrusted input, such as network interfaces, file parsers, or APIs.
9. **Enough entropy**: The harness should be designed to allow for a wide range of inputs, providing enough variability to trigger different code paths and potential bugs.
10. **Follows the code structure**: The harness should be designed to follow the structure of the codebase, making it easier to identify and target specific areas of interest.
11. **Follows code conventions**: The harness should follow the coding conventions of the project, making it easier for maintainers to understand and integrate the harness into the codebase.
12. **Does not get stuck**: The harness should be designed to avoid getting stuck on certain inputs or code paths, allowing the fuzzer to continue exploring other areas of the codebase.
13. **Includes dictionary**: The harness should include a dictionary of known inputs or patterns that are relevant to the project, helping the fuzzer to generate more effective test cases.

### Operational guidelines

- Always build and run fuzzing harnesses to validate they work. This can for example be done in a oss-fuzz environment:

```
python3 infra/helper.py build_fuzzers <project_name>
python3 infra/helper.py run_fuzzer <project_name> <fuzzer_name> -- -max_total_time=30 # run the fuzzer for 30 seconds to validate it works
python3 infra/helper.py check_build <project_name>
```

- If a fuzzer runs into a crash instantly, it's very likely wrong.
- Always document the rationale for design decisions in the fuzzing harness, and the rationale for why the harness is expected to find bugs. This can be done in a markdown file in the same directory as the fuzzing harness, or in comments in the code of the fuzzing harness itself.
- Look for function entrypoints that are exposed to untrusted input, and try to design fuzzing harnesses that target these entrypoints. This is often the most effective way to find security bugs.
- When extending existing fuzzing harnesses, always validate that the existing code coverage does not digress. You should empirically evaluate this and give a justification that no digression has happened, or if it has happened then you should give a justification for why the digression is acceptable in light of the achieved extension.
- When extending fuzzing harnesses you should give justification for the impact of bugs that they will find.

### Seed corpus and structured generation

A good harness needs a good initial corpus. Place seed files in
`$OUT/<fuzzer_name>_seed_corpus.zip` and dictionaries in
`$OUT/<fuzzer_name>.dict`.

For targets that parse a structured format (binary containers like ELF/PE, or
codec/network bitstreams, or text grammars), a few hand-picked sample files
are rarely enough: random mutation almost never gets past the parser's magic /
length / checksum checks, so the deep parsing code stays dark. The most
effective approach is a **script that constructs structurally-valid inputs
from scratch**, run from `build.sh` and appended to the corpus. It is
reproducible, needs no external samples, and lets you target specific
dark-but-reachable code identified from coverage. See the OSS-Fuzz engineer
skill's [structured seed generation
reference](../oss-fuzz-engineer/references/structured_seed_generation.md) for
the full workflow and `projects/vlc/generate_seeds.py` for a worked example.
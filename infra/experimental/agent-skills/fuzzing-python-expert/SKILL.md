---
name: fuzzing-python-expert
description:
  Use this skill to fuzz open source Python software projects using Atheris.
---

# Fuzzing Python expert

This skill provides the agent with the knowledge and tools to write, build, and
validate fuzz targets for Python projects integrated into OSS-Fuzz. Python
fuzzing uses [Atheris](https://github.com/google/atheris), which wraps libFuzzer
and instruments Python bytecode for coverage-guided fuzzing.

## Fundamental Concepts

### OSS-Fuzz base image

Python projects must use the Python base builder image:

```dockerfile
FROM gcr.io/oss-fuzz-base/base-builder-python
```

Set `language: python` in `project.yaml`.

### Harness structure

A Python fuzz target is a `.py` file (named `fuzz_<target>.py` by convention)
that follows this pattern:

```python
#!/usr/bin/python3
import sys
import atheris

# Import the module under test after atheris.instrument_imports() or within
# the atheris.instrument_all() context so bytecode is instrumented.

def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    # Extract typed values from the raw fuzzer bytes.
    value = fdp.ConsumeString(128)
    try:
        my_module.parse(value)
    except (ValueError, TypeError, KeyError):
        # Expected exceptions from invalid input are not bugs.
        pass

def main():
    atheris.instrument_all()   # instrument all loaded Python modules
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
```

### Instrumenting imports selectively

When `instrument_all()` is too broad (e.g. causes conflicts with C extensions),
instrument specific modules using the `instrument_imports()` context manager:

```python
import atheris
with atheris.instrument_imports():
    import my_module
    import my_module.subpackage
```

### FuzzedDataProvider reference

`atheris.FuzzedDataProvider` splits the raw byte stream into typed values:

| Method | Description |
|---|---|
| `ConsumeBytes(count)` | `bytes` of length count |
| `ConsumeByteList(count)` | `list[int]` of length count |
| `ConsumeString(count)` | decoded `str` (may contain surrogates) |
| `ConsumeUnicode(count)` | `str` without surrogates |
| `ConsumeUnicodeNoSurrogates(count)` | strict `str` |
| `ConsumeInt(nbytes)` | signed int from nbytes |
| `ConsumeIntInRange(min, max)` | int in range |
| `ConsumeFloat()` | float |
| `ConsumeBool()` | bool |
| `ConsumeIntList(count, nbytes)` | list of ints |
| `PickValueInList(lst)` | random element |
| `ConsumeRemainingBytes()` | all remaining bytes |

### Building in OSS-Fuzz

`build.sh` installs the target package and uses the `compile_python_fuzzer`
helper to turn each `fuzz_*.py` file into a standalone fuzzer binary in `$OUT`:

```bash
# build.sh

# Install the package under test.
pip3 install .

# Compile all fuzz targets found in $SRC.
for fuzzer in $(find $SRC -name 'fuzz_*.py'); do
    compile_python_fuzzer "$fuzzer"
done
```

`compile_python_fuzzer` handles linking against Atheris and libFuzzer and
produces an executable in `$OUT` named after the `.py` file.

### Seed corpus and dictionaries

- Place seed files in `$OUT/<fuzzer_name>_seed_corpus/` or zip them as
  `$OUT/<fuzzer_name>_seed_corpus.zip`.
- Dictionaries go to `$OUT/<fuzzer_name>.dict` — especially valuable for
  text-format parsers (JSON, XML, YAML, CSV, etc.).

## Characteristics of good Python fuzzing harnesses

1. **Instruments the right modules**: use `instrument_all()` for simplicity or
   `instrument_imports()` for targeted instrumentation. Without instrumentation
   coverage guidance is blind.
2. **Targets attack surface**: parsers, template engines, serialisation
   (pickle, JSON, YAML, XML), network protocol handling, and any API that
   accepts untrusted strings or bytes.
3. **Catches expected exceptions**: wrap target calls in `try/except` for the
   documented exception types the target raises on bad input. Only unexpected
   exceptions and hard crashes are findings.
4. **Uses `FuzzedDataProvider` for structured input** rather than feeding raw
   bytes directly to APIs that expect text — most Python APIs work on strings,
   not bytes.
5. **Avoids importing under test inside `TestOneInput`**: imports should happen
   at module level (inside the `instrument_imports()` block if used) so they
   are instrumented and not re-executed per iteration.
6. **Is fast**: avoid file I/O, network calls, or subprocess invocations inside
   `TestOneInput`.
7. **Avoids non-determinism**: no `random`, no `datetime.now()`, no
   `os.urandom()` inside the fuzz function.
8. **Enables Python coverage**: pass `enable_python_coverage=True` to
   `atheris.Setup` for bytecode-level coverage tracking.

## What Python fuzzing finds

Python is memory-safe, so the focus is on:

- **Unhandled exceptions**: `ValueError`, `RecursionError`, `MemoryError`,
  `UnicodeDecodeError`, and any exception the library should have caught and
  converted to a clean error.
- **`AssertionError`**: internal invariant violations triggered by crafted
  input.
- **Hangs / infinite loops**: detected by OSS-Fuzz's timeout.
- **Crashes in C extensions**: Python libraries that wrap C code (e.g. lxml,
  Pillow, cryptography) can still have memory-corruption bugs in their C layer,
  which Atheris will surface because libFuzzer runs the whole process.
- **Logic errors**: incorrect output, silent data corruption, wrong parsing
  results on edge-case inputs.

## Operational guidelines

- Always validate with:
  ```
  python3 infra/helper.py build_fuzzers <project>
  python3 infra/helper.py check_build <project>
  python3 infra/helper.py run_fuzzer <project> <fuzzer_name> -- -max_total_time=30
  ```
- An instant crash usually means an exception is being raised on every input.
  Run the harness locally (`python3 fuzz_target.py`) on a sample input to
  debug before building through OSS-Fuzz.
- Test the harness locally before the OSS-Fuzz build:
  ```python
  python3 fuzz_target.py <seed_file>
  ```
  Atheris supports running in single-input mode outside libFuzzer.
- Install the package locally (`pip3 install .`) and iterate quickly before
  going through the Docker build.
- When iterating locally clone the upstream repo and switch the Dockerfile from
  `RUN git clone` to `COPY` to avoid network round-trips.
- Document why each entry point was chosen and what class of bugs it may find.

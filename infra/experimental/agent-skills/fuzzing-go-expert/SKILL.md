---
name: fuzzing-go-expert
description:
  Use this skill to fuzz open source Go software projects.
---

# Fuzzing Go expert

This skill provides the agent with the knowledge and tools to write, build, and
validate fuzz targets for Go projects integrated into OSS-Fuzz. Go fuzzing uses
the native Go fuzzing framework introduced in Go 1.18, which OSS-Fuzz drives
via libFuzzer under the hood using `compile_native_go_fuzzer`.

## Fundamental Concepts

### OSS-Fuzz base image

Go projects must use the Go base builder image:

```dockerfile
FROM gcr.io/oss-fuzz-base/base-builder-go
```

Set `language: go` in `project.yaml`.

### Harness structure

Go fuzz targets are standard Go test functions with the prefix `Fuzz`, placed
in `_test.go` files (or plain `.go` files that import the testing package):

```go
package mypkg

import (
    "testing"
    _ "github.com/AdamKorcz/go-118-fuzz-build/testing" // required for OSS-Fuzz native fuzzing
)

func FuzzMyTarget(f *testing.F) {
    // Seed corpus: add representative valid inputs so the fuzzer starts
    // from a meaningful state rather than empty bytes.
    f.Add([]byte("example input"))
    f.Add([]byte("another seed"))

    f.Fuzz(func(t *testing.T, data []byte) {
        // Call into the target. Ignore expected errors; let unexpected
        // panics surface as findings.
        _, _ = ParseSomething(data)
    })
}
```

The inner `f.Fuzz` callback signature can use typed parameters instead of
`[]byte` when the target expects structured input:

```go
f.Fuzz(func(t *testing.T, s string, n int, b bool) {
    _ = ProcessRecord(s, n, b)
})
```

### Building in OSS-Fuzz

Use the `compile_native_go_fuzzer` helper in `build.sh`. It takes the package
import path, the function name, and the output binary name:

```bash
# build.sh
cp $SRC/fuzz_test.go ./          # copy harness into the module if needed
printf "package mypkg\nimport _ \"github.com/AdamKorcz/go-118-fuzz-build/testing\"\n" \
    > register.go                # required registration shim
go mod tidy
compile_native_go_fuzzer github.com/owner/repo/pkg FuzzMyTarget fuzz_my_target
```

For projects with multiple packages or multiple fuzz targets repeat the call:

```bash
compile_native_go_fuzzer github.com/owner/repo/pkg1 FuzzFoo fuzz_foo
compile_native_go_fuzzer github.com/owner/repo/pkg2 FuzzBar fuzz_bar
```

### Seed corpus and dictionaries

- Seed corpus entries go in `$OUT/<fuzzer_name>_seed_corpus/` as individual
  files, or as a zip at `$OUT/<fuzzer_name>_seed_corpus.zip`.
- Dictionaries go in `$OUT/<fuzzer_name>.dict` as plaintext token files.
- Alternatively, add seeds directly via `f.Add(...)` in the harness — these
  are compiled in and used as the initial corpus.

## Characteristics of good Go fuzzing harnesses

1. **Targets attack surface**: focus on parsers, decoders, protocol handlers,
   serialisation/deserialisation, and any API that accepts untrusted bytes or
   strings.
2. **Handles expected errors gracefully**: wrap calls in error checks and ignore
   expected error returns. Only genuine panics and unexpected behaviour are
   findings.
3. **Uses typed fuzz parameters** when the target is not purely byte-oriented —
   Go's fuzzer can mutate `string`, `int`, `bool`, `float64`, etc. directly.
4. **Avoids non-determinism**: do not use random sources, time, goroutines, or
   global state that persists between calls.
5. **Keeps the callback fast**: expensive setup (e.g. parsing config, opening
   files) belongs outside `f.Fuzz(...)`, not inside the inner function.
6. **Provides meaningful seeds**: `f.Add(...)` entries should be valid
   representative inputs so coverage grows from the start.
7. **Does not get stuck**: avoid code paths that busy-loop or block on I/O
   inside the fuzz function.
8. **Includes the registration shim**: the `import _
   "github.com/AdamKorcz/go-118-fuzz-build/testing"` blank import is required
   for OSS-Fuzz to hook into native Go fuzzing — never omit it.

## What Go fuzzing finds

Go is memory-safe, so the focus shifts from memory-corruption bugs to:

- **Panics**: index out of range, nil pointer dereference, type assertion
  failures, stack overflows — any unrecovered `panic` is a crash.
- **Logic bugs**: incorrect parsing, silent data corruption, wrong output for
  valid input.
- **Infinite loops / hangs**: code that never returns on certain inputs
  (detected by OSS-Fuzz's timeout).
- **Incorrect error handling**: code that should return an error but panics
  instead, or vice versa.

## Operational guidelines

- Always validate with:
  ```
  python3 infra/helper.py build_fuzzers <project>
  python3 infra/helper.py check_build <project>
  python3 infra/helper.py run_fuzzer <project> <fuzzer_name> -- -max_total_time=30
  ```
- An instant crash almost always means the harness itself is wrong (e.g.
  missing error handling, bad seed, wrong package path).
- Run `go vet ./...` and `go build ./...` inside the module before wrapping in
  an OSS-Fuzz build to catch compile errors early.
- When iterating locally clone the upstream repo and switch the Dockerfile from
  `RUN git clone` to `COPY` to avoid network round-trips.
- Document why each entry point was chosen and what class of bugs it may find.

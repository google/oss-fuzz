---
name: fuzzing-rust-expert
description:
  Use this skill to fuzz open source Rust software projects.
---

# Fuzzing Rust expert

This skill provides the agent with the knowledge and tools to write, build, and
validate fuzz targets for Rust projects integrated into OSS-Fuzz. Rust fuzzing
uses cargo-fuzz with the `libfuzzer_sys` crate, which drives libFuzzer.

## Fundamental Concepts

### OSS-Fuzz base image

Rust projects must use the Rust base builder image:

```dockerfile
FROM gcr.io/oss-fuzz-base/base-builder-rust
```

Set `language: rust` in `project.yaml`.

### Harness structure

Rust fuzz targets live in `fuzz/fuzz_targets/<name>.rs` within the crate being
fuzzed. The minimal harness using raw bytes:

```rust
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Call into the target. The fuzzer will mutate `data` on every iteration.
    let _ = my_crate::parse(data);
});
```

For structured fuzzing using the `arbitrary` crate (preferred when the target
expects typed input):

```rust
#![no_main]
use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;

#[derive(Debug, Arbitrary)]
struct MyInput {
    header: u8,
    payload: Vec<u8>,
    flags: u32,
}

fuzz_target!(|input: MyInput| {
    let _ = my_crate::process(input.header, &input.payload, input.flags);
});
```

The `Cargo.toml` for the fuzz directory must declare dependencies:

```toml
# fuzz/Cargo.toml
[package]
name = "my-crate-fuzz"
version = "0.0.0"
edition = "2021"
publish = false

[dependencies]
libfuzzer-sys = "0.4"
arbitrary = { version = "1", features = ["derive"] }   # only if using structured fuzzing

[dependencies.my-crate]
path = ".."

[[bin]]
name = "fuzz_target_name"
path = "fuzz_targets/fuzz_target_name.rs"
test = false
doc = false
```

### Building in OSS-Fuzz

`build.sh` uses `cargo fuzz build` and then copies binaries to `$OUT`:

```bash
# build.sh
cd $SRC/<crate-dir>
cargo fuzz build -O   # -O enables release optimisations; important for performance

FUZZ_TARGET_OUTPUT_DIR=$SRC/<crate-dir>/target/x86_64-unknown-linux-gnu/release
for f in fuzz/fuzz_targets/*.rs; do
    name=$(basename "${f%.*}")
    cp "$FUZZ_TARGET_OUTPUT_DIR/$name" "$OUT/"
done
```

If the project requires a nightly toolchain, set it in the Dockerfile:

```dockerfile
ENV RUSTUP_TOOLCHAIN=nightly
```

Or pin to a specific nightly for reproducibility:

```dockerfile
ENV RUSTUP_TOOLCHAIN=nightly-2025-07-03
```

### Seed corpus and dictionaries

- Place seed files in `fuzz/corpus/<target_name>/` within the repo; they are
  automatically picked up by cargo-fuzz and can be zipped for OSS-Fuzz.
- To ship a corpus with OSS-Fuzz copy a zip to `$OUT/<target_name>_seed_corpus.zip`.
- Dictionaries go to `$OUT/<target_name>.dict`.

## Characteristics of good Rust fuzzing harnesses

1. **Targets attack surface**: parsers, deserializers, protocol implementations,
   unsafe blocks, and any API that processes untrusted bytes.
2. **Uses structured fuzzing** (`arbitrary`) when the target expects typed data
   rather than raw bytes — this dramatically improves coverage.
3. **Handles expected errors**: `Result` and `Option` should be let-bound and
   ignored (`let _ = ...`). Only actual panics are findings.
4. **Avoids panicking on every input**: do not use `.unwrap()` or `.expect()`
   on fallible operations driven by fuzz input — these create false positives.
5. **Avoids non-determinism**: no `rand`, no system time, no thread spawning
   inside the fuzz callback.
6. **Is fast**: avoid I/O, heavy allocations, or expensive setup inside the
   callback; do those outside the `fuzz_target!` macro if needed with
   `LazyLock` / `OnceLock`.
7. **Considers `unsafe` code**: if the crate has `unsafe` blocks, write
   harnesses that exercise those paths — this is where memory bugs can still
   occur in Rust.
8. **Builds in release mode** (`-O`): fuzzing in debug mode is much slower.

## What Rust fuzzing finds

Rust's ownership model prevents most memory-corruption bugs, but fuzzing still
finds:

- **Panics**: `unwrap`/`expect` on `None`/`Err`, index out of bounds,
  arithmetic overflow in debug mode, explicit `panic!` calls.
- **`unsafe` bugs**: use-after-free, out-of-bounds reads/writes, undefined
  behaviour in `unsafe` blocks — these are real memory bugs.
- **Logic errors**: incorrect parsing, data corruption, wrong output.
- **Hangs**: infinite loops triggered by crafted input.
- **Stack overflows**: deep recursion on adversarial input.

## Operational guidelines

- Always validate with:
  ```
  python3 infra/helper.py build_fuzzers <project>
  python3 infra/helper.py check_build <project>
  python3 infra/helper.py run_fuzzer <project> <fuzzer_name> -- -max_total_time=30
  ```
- An instant crash usually means a `panic!` on every input — check for
  `.unwrap()` calls on fuzz-driven paths and replace with `if let` or `?`.
- Run `cargo build` and `cargo test` inside the crate before adding the fuzz
  harness to catch pre-existing compilation errors.
- When iterating locally clone the upstream repo and switch the Dockerfile from
  `RUN git clone` to `COPY` to avoid network round-trips.
- If the crate uses `no_std`, use `libfuzzer-sys`'s `no_std` feature and ensure
  the harness does not rely on `std`.
- Document why each entry point was chosen and what class of bugs it may find.

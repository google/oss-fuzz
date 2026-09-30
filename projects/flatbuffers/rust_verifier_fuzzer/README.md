# flatbuffers Rust verifier fuzzer

`flatbuffers_rust_verifier` fuzzes the **Rust** runtime of FlatBuffers -- a
different implementation from the C++ one `tests/fuzzer` covers, so it is not
redundant with the targets that were already here.

The property under test is the one every Rust user relies on: a buffer that
`flatbuffers::root::<T>()` accepts must be readable through the generated
**safe** accessors.  Those accessors contain no `unsafe` for the user, they only
assume that the verifier has proven every offset, vtable and vector the reader
follows to be inside the buffer.  The target therefore verifies arbitrary bytes
and then walks the whole object graph with safe accessors, including the
table -> `vtable()` -> `num_bytes()`/`object_inline_num_bytes()` path, which is
where a verifier that is too permissive shows up first as an out of bounds read.

## Layout

| Path | Purpose |
| --- | --- |
| `flatbuffers_rust_verifier.fbs` | The schema. Broad on purpose: scalars, strings, vectors of scalars/structs/tables, nested tables, structs, an enum and a union of tables. |
| `src/lib.rs` | The whole harness (`fuzz_one_input`), kept in a library target so it can also be driven by `cargo miri` or by hand. |
| `src/flatbuffers_rust_verifier_generated.rs` | **Generated at build time** by `build.sh` with the flatc built from the checkout, so the target always tests the current code generator. |
| `fuzz/` | The cargo-fuzz package; `fuzz_targets/flatbuffers_rust_verifier.rs` only wires `fuzz_one_input` into libFuzzer. |
| `seed/` | A well formed buffer of the schema, produced by `flatc -b`, used as the seed corpus. |
| `seed.json` | The input `seed/` was built from. |

## Building and running

```sh
# In the oss-fuzz checkout, after `python3 infra/helper.py build_fuzzers flatbuffers`:
python3 infra/helper.py run_fuzzer flatbuffers flatbuffers_rust_verifier
```

Or directly, from a checkout of flatbuffers with `projects/flatbuffers` applied.
The bindings are not checked in (a stale copy would keep testing an old code
generator), so they are generated first -- `build.sh` does this with the flatc it
builds from the same checkout:

```sh
cd rust_verifier_fuzzer
flatc --rust -o src flatbuffers_rust_verifier.fbs
cargo fuzz run flatbuffers_rust_verifier
```

The `flatbuffers` dependency is a path dependency on `$SRC/flatbuffers/rust/flatbuffers`,
so the runtime being fuzzed is always the one in the same checkout.

## Inspecting a finding

`cargo fuzz` cannot run under Miri, but the harness is an ordinary library, so a
tiny binary that calls `flatbuffers_rust_verifier_fuzzer::fuzz_one_input` can be
run under Miri.  An out of bounds read that a release build performs silently --
the `debug_assert!`s guarding the reads in `endian_scalar.rs` are compiled out --
is then reported as Undefined Behavior, naming the field that escaped the buffer:

```sh
RUSTFLAGS="-C debug-assertions=off" MIRIFLAGS="-Zmiri-disable-isolation" \
    cargo +nightly miri run --bin <your repro bin> -- <input>
```

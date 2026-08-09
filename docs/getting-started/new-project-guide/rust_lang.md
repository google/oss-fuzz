---
layout: default
title: Integrating a Rust project
parent: Setting up a new project
grand_parent: Getting started
nav_order: 2
permalink: /getting-started/new-project-guide/rust-lang/
---

# Integrating a Rust project
{: .no_toc}

- TOC
{:toc}
---

The process of integrating a project written in Rust with OSS-Fuzz is very
similar to the general [Setting up a new project]({{ site.baseurl
}}/getting-started/new-project-guide/) process. The key specifics of integrating
a Rust project are outlined below.

## cargo-fuzz support

Rust integration with OSS-Fuzz is expected to use [`cargo
fuzz`](https://github.com/rust-fuzz/cargo-fuzz) to build fuzzers. The `cargo
fuzz` tool will build code with required compiler flags as well as link to the
correct libFuzzer on OSS-Fuzz itself. Note that using `cargo fuzz` also makes it
quite easy to run the fuzzers locally yourself if you get a failing test case!

## Project files

First you'll want to follow the [setup instructions for `cargo fuzz`
itself](https://rust-fuzz.github.io/book/). Afterwards your project should have:

* A top-level `fuzz` directory.
* A `fuzz/Cargo.toml` manifest which pulls in necessary dependencies to fuzz.
* Some `fuzz/fuzz_targets/*.rs` files which are the fuzz targets that will be
  compiled and run on OSS-Fuzz.

Note that you can customize this layout as well, but you'll need to edit some
the scripts below to integrate into OSS-Fuzz.

### project.yaml

The `language` attribute must be specified.

```yaml
language: rust
```

The only supported fuzzing engine and sanitizer are `libfuzzer` and `address`,
respectively.
[Example](https://github.com/google/oss-fuzz/blob/12ef3654b3e9adfd20b5a6afdde54819ba71493d/projects/serde_json/project.yaml#L3-L6)

```yaml
sanitizers:
  - address
fuzzing_engines:
  - libfuzzer
```

### Dockerfile

The Dockerfile should start by `FROM gcr.io/oss-fuzz-base/base-builder-rust`

The OSS-Fuzz builder image has the latest nightly release of Rust as well as
`cargo fuzz` pre-installed and in `PATH`. In the `Dockerfile` for your project
all you'll need to do is fetch the latest copy of your code and install any
system dependencies necessary to build your project.
[Example](https://github.com/google/oss-fuzz/blob/12ef3654b3e9adfd20b5a6afdde54819ba71493d/projects/serde_json/Dockerfile#L18-L20)

```dockerfile
RUN git clone --depth 1 https://github.com/serde-rs/json json
```

### build.sh

Here it's expected that you'll build the fuzz targets for your project and then
copy the final binaries into the output directory.
[Example](https://github.com/google/oss-fuzz/blob/12ef3654b3e9adfd20b5a6afdde54819ba71493d/projects/serde_json/build.sh#L20):

```sh
cd $SRC/json
cargo fuzz build -O
cp fuzz/target/x86_64-unknown-linux-gnu/release/from_slice $OUT/
```

Note that you likely want to pass the `-O` flag to `cargo fuzz build` which
builds fuzzers in release mode. You may also want to pass the
`--debug-assertions` flag to enable more checks while fuzzing. In this example
the `from_slice` binary is the fuzz target.

With some bash-fu you can also automatically copy over all fuzz targets into
the output directory so when you add a fuzz target to your project it's
automatically integrated into OSS-Fuzz:

```sh
FUZZ_TARGET_OUTPUT_DIR=target/x86_64-unknown-linux-gnu/release
for f in fuzz/fuzz_targets/*.rs
do
    FUZZ_TARGET_NAME=$(basename ${f%.*})
    cp $FUZZ_TARGET_OUTPUT_DIR/$FUZZ_TARGET_NAME $OUT/
done
```

## Writing fuzzers using a test-style strategy

In Rust you will often have tests written in a way so they are only 
compiled into the final binary when build in test-mode. This is, achieved by
wrapping your test code in `cfg(test)`, e.g.
```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    ...
```

Cargo-fuzz automatically enables the `fuzzing` feature, which means you can
follow a similar strategy to writing fuzzers as you do when writing tests.
Specifically, you can create modules wrapped in the `fuzzing` feature:
```rust
#[cfg(fuzzing)]
pub mod fuzz_logic {
    use super::*;

    ...
```
and then call the logic within `fuzz_logic` from your fuzzer. 

Furthermore, within your `.toml` files, you can then specify fuzzing-specific
dependencies by wrapping them as follows:
```
[target.'cfg(fuzzing)'.dependencies]
```
similar to how you wrap test-dependencies as follows:
```
[dev-dependencies]
```

Finally, you can also combine the testing logic you have and the fuzz logic. This
can be achieved simply by using 
```rust
#[cfg(any(test, fuzzing))]
```

A project that follows this structure is Linkerd2-proxy and the project files can be
seen [here](https://github.com/google/oss-fuzz/tree/master/projects/linkerd2-proxy).

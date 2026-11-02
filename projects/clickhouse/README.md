# ClickHouse OSS-Fuzz integration

This integration builds ClickHouse's existing in-process libFuzzer targets.
BuzzHouse is complementary: it generates database-aware SQL workloads against a
server; these harnesses exercise parser, decoder and serialization interfaces.

## Build environment

Use Linux x86-64 with sufficient memory and disk for ClickHouse and its vendored
dependencies. The image installs the Rust toolchain selected by ClickHouse's
`contrib/corrosion-cmake/CMakeLists.txt`, including `rust-src` for sanitized Rust
standard-library builds. It does not maintain a separate Rust version pin.

Build objects live under `$WORK/clickhouse`, which the local helper persists
between containers. Reuse the image cache for build-script edits and keep the
workspace for same-configuration iterations. Use `--clean` when changing
sanitizers or when a clean validation build is required.


## Fast regression checks

With `cmake`, `ninja`, Clang/LLVM, `zip`, `strip`, and `/usr/bin/ccache`:

```sh
python3 projects/clickhouse/build_test.py -v
```

These tests compile real small executables through the build script. They cover
the CI target bound, optional targets absent from the configured build,
missing-dictionary failure and recovery, preservation of the compiler policy,
and staging every source and header referenced by coverage mappings at the path
the report generator uses. They do not replace a ClickHouse build, sanitizer
checks or hosted execution.
The path-filtered
`clickhouse_build_tests.yml` workflow runs them for this integration's PR changes;
general infrastructure test discovery still excludes `projects/`.

## Integration validation

```sh
# Refresh only the base tag this project uses, then take a fresh source snapshot.
docker pull gcr.io/oss-fuzz-base/base-builder:ubuntu-24-04
python3 infra/helper.py build_image --no-pull clickhouse

# Subsequent build-script edits: reuse the source/toolchain image layers.
python3 infra/helper.py build_image --cache --no-pull clickhouse

# Short feedback loop: two eligible targets, not the complete target set.
python3 infra/helper.py build_fuzzers --sanitizer address -e OSS_FUZZ_CI=1 clickhouse
python3 infra/helper.py check_build --sanitizer address clickhouse

# Full intended target set. Repeat with memory and undefined, checking each
# result before the next build replaces the output directory.
python3 infra/helper.py build_fuzzers --clean --sanitizer address clickhouse
python3 infra/helper.py check_build --sanitizer address clickhouse

python3 infra/helper.py build_fuzzers --clean --sanitizer coverage clickhouse
# Coverage reads per-target corpus directories, not the packaged zip files.
mkdir -p build/corpus/clickhouse
for fuzzer in build/out/clickhouse/*_fuzzer; do
  mkdir -p "build/corpus/clickhouse/$(basename "$fuzzer")"
done
for seed in build/out/clickhouse/*_seed_corpus.zip; do
  target="$(basename "$seed" _seed_corpus.zip)"
  python3 -m zipfile -e "$seed" "build/corpus/clickhouse/$target"
done
python3 infra/helper.py coverage --no-corpus-download --no-serve \
  --base-image-tag ubuntu-24-04 clickhouse

```

Coverage requires suitable local corpora. The extraction above uses packaged
public seeds; `--no-corpus-download` avoids needing hosted-corpus access. The
build stages exactly the source files named by LLVM's coverage mappings,
including generated files already present in the build tree. Targets without
local corpora may produce no profile. Check the generated
`build/out/clickhouse/report/` and `fuzzer_stats/` contents: a successful coverage
build alone does not prove a report was generated or useful code was reached.

Only configured targets originating under ClickHouse's `src` and `programs` are
selected. Every selected target must build successfully. Only selected binaries,
their options, referenced dictionaries and available seed corpora are packaged.
Public SQL tests seed lexer/select/create parser targets; committed target seed
directories are also retained. Source presence alone does not imply coverage:
optional libraries can disable targets, and some harnesses have configuration-
dependent no-op paths that need coverage inspection.

## Reports and hosted verification

The existing `project.yaml` sends new bug notifications to
`security@clickhouse.com` and its `auto_ccs`. Those contacts receive ClusterFuzz
access through their Google accounts. Crash reports are initially restricted;
this project does not enable GitHub issue mirroring. Do not publish private
reports, reproduction inputs or corpora in integration PRs.

Build status is public at
https://oss-fuzz-build-logs.storage.googleapis.com/index.html#clickhouse.
After an approved merge, verify the deployed source revision and recent target
executions at https://oss-fuzz.com/. Local build and startup checks do not prove
that hosted workers have adopted the new binaries.

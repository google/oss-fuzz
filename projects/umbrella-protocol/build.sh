#!/bin/bash -eu
# Build script для Google OSS-Fuzz интеграции Umbrella Protocol.
# Build script for the Google OSS-Fuzz integration of Umbrella Protocol.
#
# Этап 9 Hardening, блок 9.6 — OSS-Fuzz onboarding.
# Stage 9 Hardening, block 9.6 — OSS-Fuzz onboarding.
#
# Запускается из Google OSS-Fuzz CI после Dockerfile build phase. Переменные
# окружения OSS-Fuzz: $SRC = /src, $WORK = /work, $OUT = /out (выходная
# директория для libFuzzer binaries). См.
# <https://google.github.io/oss-fuzz/getting-started/new-project-guide/rust-lang/>
# раздел "build.sh".
#
# Invoked by Google OSS-Fuzz CI after the Dockerfile build phase. OSS-Fuzz
# environment: $SRC = /src, $WORK = /work, $OUT = /out (output directory for
# libFuzzer binaries). See
# <https://google.github.io/oss-fuzz/getting-started/new-project-guide/rust-lang/>
# section "build.sh".

# Перейти в sub-workspace umbrella-fuzz-targets — отдельный Cargo workspace
# для libfuzzer-sys (требует nightly Rust + isolation от main stable workspace
# MSRV 1.87 per crates/umbrella-fuzz/fuzz/Cargo.toml).
#
# Switch to the umbrella-fuzz-targets sub-workspace — a separate Cargo
# workspace for libfuzzer-sys (requires nightly Rust + isolation from the main
# stable workspace MSRV 1.87 per crates/umbrella-fuzz/fuzz/Cargo.toml).
cd "$SRC/umbrella-protocol/crates/umbrella-fuzz/fuzz"

# Build все 23 fuzz target'а одной командой. Флаг `-O` включает release
# оптимизации; --debug-assertions полезен для catch'инга debug-only invariants.
# Feature `pq` активируется автоматически через umbrella-fuzz dep declaration
# (crates/umbrella-fuzz/fuzz/Cargo.toml: `features = ["pq"]`).
#
# Build all 23 fuzz targets in one pass. The `-O` flag enables release
# optimisations; `--debug-assertions` is helpful for catching debug-only
# invariants. The `pq` feature is activated automatically through the
# umbrella-fuzz dep declaration (crates/umbrella-fuzz/fuzz/Cargo.toml:
# `features = ["pq"]`).
cargo fuzz build -O --debug-assertions

# Скопировать сборные libFuzzer binary targets в $OUT. Шаблон автоматически
# обнаруживает все `fuzz_targets/*.rs` и копирует соответствующий compiled
# binary. Совместимо с future targets без изменения скрипта.
#
# Copy the built libFuzzer binary targets into $OUT. The pattern auto-discovers
# all `fuzz_targets/*.rs` and copies the corresponding compiled binary,
# remaining compatible with future targets without script changes.
FUZZ_TARGET_OUTPUT_DIR="target/x86_64-unknown-linux-gnu/release"
for f in fuzz_targets/*.rs; do
    FUZZ_TARGET_NAME=$(basename "${f%.*}")
    cp "$FUZZ_TARGET_OUTPUT_DIR/$FUZZ_TARGET_NAME" "$OUT/"
done

# Опциональная корпус-инициализация. Initial corpus seeds — KAT vectors из
# crates/umbrella-vectors/data/ для xwing / hybrid-sig / KT entries — могут
# быть подгружены через `cp -r ../../umbrella-vectors/data $OUT/<target>_seed_corpus.zip`
# при необходимости. На день block 9.6 corpus deferred — Google OSS-Fuzz
# самостоятельно генерирует initial corpus из coverage feedback после первых
# 1-2 циклов запуска. Detailed corpus seeding fix-on-sight для post-block 9.6
# revision (TODO.md).
#
# Optional corpus initialisation. Initial corpus seeds — KAT vectors from
# crates/umbrella-vectors/data/ for xwing / hybrid-sig / KT entries — can be
# loaded via
# `cp -r ../../umbrella-vectors/data $OUT/<target>_seed_corpus.zip`
# if needed. At block 9.6 the corpus seeding is deferred — Google OSS-Fuzz
# generates an initial corpus from coverage feedback after the first 1-2
# fuzzing cycles. Detailed corpus seeding is a fix-on-sight item for a
# post-block 9.6 revision (TODO.md).

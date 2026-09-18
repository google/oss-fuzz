#!/bin/bash -eu
# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################
set -euo pipefail

# Zephyr's upstream fuzzing path is `native_sim/native/64` driven by
# CONFIG_ARCH_POSIX_LIBFUZZER, which hard-codes `-fsanitize=fuzzer` into
# the link. That makes libFuzzer the only currently supported engine.
if [ "${FUZZING_ENGINE:-libfuzzer}" != "libfuzzer" ]; then
    echo "Skipping unsupported FUZZING_ENGINE=$FUZZING_ENGINE (Zephyr only" \
         "supports libFuzzer for now)."
    exit 0
fi

export ZEPHYR_BASE="$SRC/zephyrproject/zephyr"
export ZEPHYR_TOOLCHAIN_VARIANT="host/llvm"

# Map OSS-Fuzz's $SANITIZER onto Zephyr's Kconfig sanitizer options.
# Zephyr's arch/posix/CMakeLists.txt builds the `-fsanitize=...` arg from
# these CONFIG_* values, so we drive the sanitizer choice through Kconfig
# instead of CFLAGS/CXXFLAGS to avoid double-instrumentation.
SANITIZER_CONF="-DCONFIG_ARCH_POSIX_LIBFUZZER=y"
case "${SANITIZER:-address}" in
    address)   SANITIZER_CONF="$SANITIZER_CONF -DCONFIG_ASAN=y" ;;
    undefined) SANITIZER_CONF="$SANITIZER_CONF -DCONFIG_UBSAN=y" ;;
    memory)    SANITIZER_CONF="$SANITIZER_CONF -DCONFIG_MSAN=y" ;;
    coverage)  ;;
    *) echo "Unsupported SANITIZER=$SANITIZER"; exit 1 ;;
esac

# Zephyr drives sanitizer/fuzzer flags from Kconfig and supplies its own
# toolchain config files via clang's `--config`. Letting OSS-Fuzz's pre-set
# CFLAGS/CXXFLAGS leak through causes duplicate `-fsanitize=` flags and
# `--config` clashes, so we clear them here.
unset CFLAGS CXXFLAGS

build_fuzzer() {
    local sample_path="$1"   # e.g. samples/subsys/debug/fuzz
    local fuzzer_name="$2"   # output binary name in $OUT
    local build_dir="$WORK/build-$fuzzer_name"
    rm -rf "$build_dir"

    cd "$ZEPHYR_BASE"
    west build -d "$build_dir" -b native_sim/native/64 "$sample_path" \
        -- $SANITIZER_CONF

    cp "$build_dir/zephyr/zephyr.exe" "$OUT/$fuzzer_name"
}

# Upstream fuzz harness: drives the OS through an interrupt and exercises
# kernel scheduling, IRQ dispatch and printk on every input.
build_fuzzer "samples/subsys/debug/fuzz" "zephyr_fuzz_sample"

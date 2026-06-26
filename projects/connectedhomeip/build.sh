#!/bin/bash -eu
# Copyright 2023 Google LLC
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


# workaround to get Fuzz Introspector to build; making it link with lld instead of the environment's gold linker which gives an error
if [ "$SANITIZER" == "introspector" ]; then
  export CFLAGS=$(echo "$CFLAGS" | sed 's/gold/lld/g')
  export CXXFLAGS=$(echo "$CXXFLAGS" | sed 's/gold/lld/g')
fi

cd $SRC/connectedhomeip

# Preserve the OSS-Fuzz-provided toolchain settings. The pw_fuzzer / FuzzTest toolchain
# (//build/toolchain/pw_fuzzer) reads $CC/$CXX/$CFLAGS/$CXXFLAGS at `gn gen` time so its
# libFuzzer runtime matches OSS-Fuzz's instrumentation; Pigweed's activate.sh may change
# the environment, so capture these first and restore them before `gn gen`.
OSS_FUZZ_CC="${CC:-}"
OSS_FUZZ_CXX="${CXX:-}"
OSS_FUZZ_CFLAGS="${CFLAGS:-}"
OSS_FUZZ_CXXFLAGS="${CXXFLAGS:-}"

# MemorySanitizer needs every linked dependency instrumented. Build the MSAN-instrumented
# dependency sysroot (GLib/OpenSSL/zlib/libffi/pcre2) HERE rather than in the Dockerfile: the
# deps' ./configure and meson run MSAN-instrumented test binaries, which require lowered ASLR
# entropy. The OSS-Fuzz `compile` wrapper sets vm.mmap_rnd_bits=28 and runs this privileged
# before invoking build.sh; `docker build` can do neither, so a Dockerfile-time bake fails.
# Done before activate.sh so it uses OSS-Fuzz's clang ($CC/$CFLAGS, which already carry
# -fsanitize=memory) and the system meson/ninja. libc++ is NOT built -- OSS-Fuzz ships an
# instrumented one at /usr/msan (applied via -stdlib=libc++); only the C deps are built, with
# the same $CFLAGS as the fuzzers. Adds ~5-15 min to the memory build.
MSAN_SYSROOT="$SRC/msan-sysroot"
if [ "${SANITIZER:-}" == "memory" ]; then
  scripts/build/build_msan_sysroot.sh --oss-fuzz --out-dir "$MSAN_SYSROOT"
fi

# Activate Pigweed environment
set +u
PW_ENVSETUP_QUIET=1 source scripts/activate.sh
set -u

#This adds zap-cli to PATH, needed for fuzzing all-clusters-app
export PATH="/src/connectedhomeip/.environment/cipd/packages/zap/:$PATH"

# Restore the OSS-Fuzz toolchain settings so `gn gen` (run below while the Pigweed
# environment is active) sees them.
export CC="$OSS_FUZZ_CC"
export CXX="$OSS_FUZZ_CXX"
export CFLAGS="$OSS_FUZZ_CFLAGS"
export CXXFLAGS="$OSS_FUZZ_CXXFLAGS"

# MemorySanitizer: link the instrumented dependency sysroot built above instead of the
# uninstrumented system GLib/OpenSSL/zlib/etc, and apply the MSAN ignorelist. Without
# instrumented dependencies, MSAN reports endless false positives from uninstrumented library
# internals -- the reason MSAN was previously disabled for this project. PKG_CONFIG_PATH makes
# Matter's GN pick up the instrumented static libs; it must be exported before `gn gen`.
#
# -DCHIP_MEMORY_SANITIZER_ENABLED=1 turns on Matter's in-tree MSan instrumentation guards (e.g.
# the if_nameindex() unpoisoning in InetInterfaceImplDefault.cpp). That macro is normally defined
# only by the GN sanitize_memory config (the local MSan unit-test build); OSS-Fuzz enables MSan
# via $CFLAGS instead, so we set it here. It flows to every TU through the global oss_fuzz config.
if [ "${SANITIZER:-}" == "memory" ]; then
  export PKG_CONFIG_PATH="$MSAN_SYSROOT/lib/pkgconfig:$MSAN_SYSROOT/lib64/pkgconfig:${PKG_CONFIG_PATH:-}"
  msan_ignorelist="$SRC/connectedhomeip/build/config/compiler/msan_ignorelist.txt"
  export CFLAGS="$CFLAGS -fsanitize-ignorelist=$msan_ignorelist -DCHIP_MEMORY_SANITIZER_ENABLED=1"
  export CXXFLAGS="$CXXFLAGS -fsanitize-ignorelist=$msan_ignorelist -DCHIP_MEMORY_SANITIZER_ENABLED=1"
fi

# Create a build directory with the following options:
# - `oss_fuzz` enables OSS-Fuzz build
# - `is_clang` selects clang toolchains (does not support AFL fuzzing engine)
# - `enable_rrti` enables RTTI to support UBSan build
# - `pw_enable_fuzz_test_targets` builds the pw_fuzzer / Google FuzzTest targets in
#   libFuzzer-compatibility mode, in addition to the legacy libFuzzer targets.
# - `chip_enable_thread_safety_checks` disabled since OSS-Fuzz clang does not
#   seem to currently support or need this analysis
# - `chip_enable_openthread` disabled since OSS-Fuzz clang issues a compile
#   error on GenericConnectivityManagerImpl_Thread.ipp and current fuzzing
#   does not differentiate between thread/Wifi/TCP/UDP/BLE connectivity
#   implementations.
# - `target_ldflags` forces compiler to use LLVM's linker
gn gen out/fuzz_targets \
  --args="
    oss_fuzz=true \
    is_clang=true \
    enable_rtti=true \
    pw_enable_fuzz_test_targets=true \
    chip_enable_thread_safety_checks=false \
    chip_enable_thread=false \
    target_ldflags=[\"-fuse-ld=lld\"]"

# Deactivate Pigweed environment to use OSS-Fuzz toolchains
deactivate

# Compile the legacy libFuzzer fuzz targets
ninja -C out/fuzz_targets fuzz_tests

cp out/fuzz_targets/tests/* $OUT/

# Compile the pw_fuzzer / Google FuzzTest targets and generate one OSS-Fuzz fuzz target per
# FUZZ_TEST case. A FuzzTest binary hosts many cases and is run one case at a time
# (--fuzz=<Suite.Case>), so gen_pw_fuzztest_oss_fuzz_wrappers.sh emits a detectable wrapper
# per case (see that script). FuzzTest binaries are libFuzzer-compatible, so only build them
# for the libFuzzer engine; honggfuzz/centipede cannot drive a libFuzzer-compatibility binary.
if [[ "${FUZZING_ENGINE:-libfuzzer}" == "libfuzzer" ]]; then
  ninja -C out/fuzz_targets pw_fuzz_tests
  bash "$SRC/connectedhomeip/scripts/build/gen_pw_fuzztest_oss_fuzz_wrappers.sh" \
    "$OUT" out/fuzz_targets/chip_pw_fuzztest/tests/fuzz-*-pw

  # The FuzzChipCert harness seeds from a source-tree directory that is not present in the
  # OSS-Fuzz runner (which runs fuzzers without the build tree). Provide those seeds the
  # location-independent OSS-Fuzz way -- one <target>_seed_corpus.zip per generated chip-cert
  # target -- so libFuzzer uses them as the initial corpus. (The harness itself tolerates the
  # directory being absent.)
  chip_cert_seeds=credentials/test/operational-certificates-error-cases
  if [ -d "$chip_cert_seeds" ]; then
    for wrapper in "$OUT"/fuzz-chip-cert-pw@*; do
      [ -e "$wrapper" ] || continue
      python3 -m zipfile -c "${wrapper}_seed_corpus.zip" "$chip_cert_seeds"/
    done
  fi
fi

# Copy some GLib and GIO runtime libraries into $OUT so fuzzed all-clusters app can run under
# OSS-Fuzz base-runner, which does not provide these libraries.
#
# Skipped for MemorySanitizer: these are the uninstrumented system GLib libraries, and injecting
# them at runtime reintroduces exactly the false positives MSAN was disabled for. The MSAN build
# links the instrumented GLib statically from the sysroot (see the SANITIZER==memory block
# above), so no runtime .so is needed.
if [ "${SANITIZER:-}" != "memory" ]; then
  mkdir -p $OUT/lib
  cp /usr/lib/x86_64-linux-gnu/libgio-2.0.so.0 $OUT/lib/
  cp /usr/lib/x86_64-linux-gnu/libgobject-2.0.so.0 $OUT/lib/
  cp /usr/lib/x86_64-linux-gnu/libglib-2.0.so.0 $OUT/lib/
  cp /usr/lib/x86_64-linux-gnu/libgmodule-2.0.so.0 $OUT/lib/

  # Set an rpath on the fuzz target binaries (ELF only; the FuzzTest wrapper scripts and the
  # non-executable shared FuzzTest binaries are matched too — patchelf on the shared ELF, the
  # `file ... ELF` guard skips the shell-script wrappers).
  for f in $OUT/fuzz-*; do
      file "$f" | grep -q "ELF" && patchelf --set-rpath '$ORIGIN/lib' "$f"
  done
  patchelf --set-rpath '$ORIGIN' $OUT/lib/*.so* 2>/dev/null
fi

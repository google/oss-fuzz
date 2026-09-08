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

cd $SRC/xla

# Stage the fuzz harness sources + BUILD into the freshly-cloned xla tree.
# OSS-Fuzz copies COPY build.sh contents into $SRC/, but other staged files
# need to be packaged into the project's build context. The harness sources
# under xla/fuzz/ ship from the openxla/xla upstream once PR-A merges; until
# then, expect them to be present in the cloned tree at build time.
test -f xla/fuzz/BUILD || {
  echo "ERROR: xla/fuzz/BUILD missing — PR-A (upstream harness landing) must merge before this OSS-Fuzz integration builds cleanly."
  exit 1
}

# Build flags for libfuzzer + ASAN. base-builder sets $CFLAGS / $CXXFLAGS /
# $LIB_FUZZING_ENGINE; we pass the fuzzer-link engine via --linkopt and the
# sanitizer-instrumentation flags via --copt so bazel sees them on every cc_*
# rule.
bazel \
    --host_jvm_args=-Xmx10g \
    build \
    -c opt \
    --copt=-fsanitize=fuzzer-no-link \
    --copt=-fsanitize=address \
    --copt=-fno-omit-frame-pointer \
    --linkopt=-fsanitize=fuzzer \
    --linkopt=-fsanitize=address \
    --cxxopt=-stdlib=libc++ \
    --linkopt=-stdlib=libc++ \
    --linkopt=-Wl,-rpath,\$ORIGIN \
    --host_cxxopt=-stdlib=libc++ \
    --host_linkopt=-stdlib=libc++ \
    //xla/fuzz:hlo_parser_fuzz \
    //xla/fuzz:hlo_proto_fuzz

cp bazel-bin/xla/fuzz/hlo_parser_fuzz $OUT/
cp bazel-bin/xla/fuzz/hlo_proto_fuzz  $OUT/

# xla's hermetic clang toolchain dynamically links libc++/libc++abi/libunwind
# from external/llvm18_linux_x86_64/lib/. base-runner doesn't ship these, so
# copy them alongside the fuzzer binaries (base-runner adds $OUT to LD_LIBRARY_PATH).
for libname in libc++.so.1 libc++abi.so.1 libunwind.so.1; do
  # Prefer the copy inside the Bazel output tree (deterministic version).
  src=$(find /root/.cache/bazel/_bazel_root -name "$libname" \
        2>/dev/null | sort | head -1)
  # Fall back to full filesystem search if not found in Bazel cache.
  if [ -z "$src" ]; then
    src=$(find / -name "$libname" 2>/dev/null | sort | head -1)
  fi
  if [ -n "$src" ]; then
    cp -L "$src" "$OUT/" && echo "staged $libname from $src"
  else
    echo "WARN: $libname not found on build container"
  fi
done


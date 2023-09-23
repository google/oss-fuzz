# Copyright 2020 Google Inc.
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

export CXXFLAGS="$CXXFLAGS -std=c++14 -O0"

readonly EXTRA_BAZEL_FLAGS="$(
for f in ${CFLAGS}; do
  echo "--conlyopt=${f}" "--linkopt=${f}"
done
for f in ${CXXFLAGS}; do
  echo "--cxxopt=${f}" "--linkopt=${f}"
done

if [ "$FUZZING_ENGINE" = "libfuzzer" ]
then
  echo "--cxxopt=-fsanitize=fuzzer-no-link"
  echo "--linkopt=\"$(find $(llvm-config --libdir) -name libclang_rt.fuzzer-x86_64.a| head -1)\""
fi
if [ "$FUZZING_ENGINE" = "honggfuzz" ]
then
  echo "--cxxopt=-fsanitize-coverage=trace-pc-guard,indirect-calls,trace-cmp"
  echo "--linkopt=\"$(find . -name honggfuzz.a)\""
fi
if [ "$FUZZING_ENGINE" = "afl" ]
then
  echo "--cxxopt=-fsanitize=fuzzer-no-link"
  echo "--cxxopt=-fsanitize-coverage=trace-pc-guard,indirect-calls,trace-cmp"
  echo "--linkopt=\"$(find . -name libAFLDriver.a | head -1)\""
  echo "--linkopt=\"$(find . -name afl-compiler-rt-64.o | head -1)\""
fi

if [ "$SANITIZER" = "undefined" ]
then
  echo "--cxxopt=-fsanitize=undefined --linkopt=-fsanitize=undefined"
  echo "--linkopt=\"$(find $(llvm-config --libdir) -name libclang_rt.ubsan_standalone_cxx-x86_64.a | head -1)\""
fi
if [ "$SANITIZER" = "address" ]
then
  echo "--cxxopt=-fsanitize=address --linkopt=-fsanitize=address"
  echo "--linkopt=\"$(find $(llvm-config --libdir) -name libclang_rt.asan_cxx-x86_64.a | head -1)\""
fi

)"

declare FUZZ_TARGETS=("string_escape_fuzzer" "string_utilities_fuzzer" "ascii_fuzzer" "algorithm_fuzzer" "algorithm_container_fuzzer" "crc_fuzzer" "flags_fuzzer")

bazel build \
	--verbose_failures \
	--dynamic_mode=off \
	--spawn_strategy=standalone \
	--genrule_strategy=standalone \
	--strip=never \
	--linkopt=-pthread \
  --linkopt=-lc++ \
  --linkopt=-ldl \
	${EXTRA_BAZEL_FLAGS} \
	${FUZZ_TARGETS[*]}


if [ "$SANITIZER" = "coverage" ]
then
  # The build invoker looks for sources in $SRC, but it turns out that we need
  # to not be buried under src/, paths are expected at out/proc/self/cwd by
  # the profiler.
  declare -r REMAP_PATH="${OUT}/proc/self/cwd"
  mkdir -p "${REMAP_PATH}"
  mkdir -p "${REMAP_PATH}/external/com_google_absl"
  rsync -av "${SRC}"/abseil-cpp/absl "${REMAP_PATH}/external/com_google_absl"

  declare -r RSYNC_FILTER_ARGS=("--include" "*.h" "--include" "*.cc" "--include" \
    "*.hpp" "--include" "*.cpp" "--include" "*.c" "--include" "*/" "--exclude" "*")
  rsync -avLk "${RSYNC_FILTER_ARGS[@]}" "${SRC}"/bazel-out "${REMAP_PATH}"
  rsync -avLkR "${RSYNC_FILTER_ARGS[@]}" "${HOME}" "${OUT}"
  rsync -avLkR "${RSYNC_FILTER_ARGS[@]}" /tmp "${OUT}"

  cp *fuzzer.cc "${OUT}/proc/self/cwd"
fi

cp "./bazel-bin/"*fuzzer "${OUT}/"

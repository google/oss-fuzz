#!/bin/bash -eu
# Copyright 2018 Google Inc.
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

declare -r FUZZ_TARGET_QUERY='
  let all_fuzz_tests = attr(tags, "fuzz_target", "...") in
  $all_fuzz_tests - attr(tags, "no_fuzz", $all_fuzz_tests)
'
declare -r OSS_FUZZ_TARGETS="$(bazel query "${FUZZ_TARGET_QUERY}" | sed 's/$/_oss_fuzz/')"

declare -r EXTRA_BAZEL_FLAGS="$(
if [ "$SANITIZER" = "undefined" ]
then
  # Bazel uses clang to link binary, which does not link clang_rt ubsan library for C++ automatically.
  # See issue: https://github.com/bazelbuild/bazel/issues/8777
  echo "--linkopt=\"$(find $(llvm-config --libdir) -name libclang_rt.ubsan_standalone_cxx-x86_64.a | head -1)\""
elif [ "$SANITIZER" = "address" ]
then
  echo "--copt=-D__SANITIZE_ADDRESS__" "--copt=-DADDRESS_SANITIZER=1" "--linkopt=-fsanitize=address"
fi
)"

# The Envoy build configuration may clobber CFLAGS/CXXFLAGS, so we use separate
# environment variables that are understood by rules_fuzzing.
export FUZZING_CFLAGS="$CFLAGS"
export FUZZING_CXXFLAGS="$CXXFLAGS"

# Benchmark about 3 GB per CPU (10 threads for 28.8 GB RAM)
# TODO(asraa): Remove deprecation warnings when Envoy and deps moves to C++17
bazel build --verbose_failures --dynamic_mode=off \
  --spawn_strategy=standalone --genrule_strategy=standalone \
  --local_cpu_resources=HOST_CPUS*0.32 \
  --//source/extensions/wasm_runtime/v8:enabled=false \
  --build_tag_filters=-no_asan --config=oss-fuzz \
  ${EXTRA_BAZEL_FLAGS} \
  ${OSS_FUZZ_TARGETS[*]}

# Profiling with coverage requires that we resolve+copy all Bazel symlinks and
# also remap everything under proc/self/cwd to correspond to Bazel build paths.
if [ "$SANITIZER" = "coverage" ]
then
  # The build invoker looks for sources in $SRC, but it turns out that we need
  # to not be buried under src/, paths are expected at out/proc/self/cwd by
  # the profiler.
  declare -r REMAP_PATH="${OUT}/proc/self/cwd"
  mkdir -p "${REMAP_PATH}"
  # For .cc, we only really care about source/ today.
  rsync -av "${SRC}"/envoy/source "${REMAP_PATH}"
  rsync -av "${SRC}"/envoy/test "${REMAP_PATH}"
  # Remove filesystem loop manually.
  rm -rf "${SRC}"/envoy/bazel-envoy/external/envoy
  # Clean up symlinks with a missing referrant.
  find "${SRC}"/envoy/bazel-envoy/external -follow -type l -ls -delete || echo "Symlink cleanup soft fail"
  rsync -avLk "${SRC}"/envoy/bazel-envoy/external "${REMAP_PATH}"
  # For .h, and some generated artifacts, we need bazel-out/. Need to heavily
  # filter out the build objects from bazel-out/. Also need to resolve symlinks,
  # since they don't make sense outside the build container.
  declare -r RSYNC_FILTER_ARGS=("--include" "*.h" "--include" "*.cc" "--include" \
    "*.hpp" "--include" "*.cpp" "--include" "*.c" "--include" "*/" "--exclude" "*")
  rsync -avLk "${RSYNC_FILTER_ARGS[@]}" "${SRC}"/envoy/bazel-out "${REMAP_PATH}"
  rsync -avLkR "${RSYNC_FILTER_ARGS[@]}" "${HOME}" "${OUT}"
  rsync -avLkR "${RSYNC_FILTER_ARGS[@]}" /tmp "${OUT}"
fi

for oss_fuzz_archive in $(find bazel-bin/ -name '*_oss_fuzz.tar'); do
    tar -xvf "${oss_fuzz_archive}" -C "${OUT}"
done

# Cleanup bazel- symlinks to avoid oss-fuzz trying to copy out of the build
# cache.
rm -f bazel-*

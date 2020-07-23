#!/bin/bash -eu
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

# This build.sh is partly modeled after that of envoyproxy:
# https://github.com/google/oss-fuzz/blob/master/projects/envoy/build.sh

export CFLAGS="$CFLAGS"
export CXXFLAGS="$CXXFLAGS"

# Copy $CFLAGS and $CXXFLAGS into Bazel command-line flags, for both
# compilation and linking.
#
# Some flags, such as `-stdlib=libc++`, generate warnings if used on a C source
# file. Since the build runs with `-Werror` this will cause it to break, so we
# use `--conlyopt` and `--cxxopt` instead of `--copt`.
declare -r EXTRA_BAZEL_FLAGS="$(
for f in ${CFLAGS}; do
  echo "--conlyopt=${f}" "--linkopt=${f}"
done
for f in ${CXXFLAGS}; do
  echo "--cxxopt=${f}" "--linkopt=${f}"
done

# Questionable code block currently under investigation.
if [ "$SANITIZER" = "undefined" ]
then
  # Bazel uses clang to link binary, which does not link clang_rt ubsan library for C++ automatically.
  # See issue: https://github.com/bazelbuild/bazel/issues/8777
  # echo "--linkopt=\"$(find $(llvm-config --libdir) -name libclang_rt.ubsan_standalone_cxx-x86_64.a | head -1)\""

  # Modeled after: https://github.com/envoyproxy/envoy/blob/master/bazel/setup_clang.sh
  echo "--linkopt=-L$(dirname $(find $(llvm-config --libdir) -name libclang_rt.ubsan_standalone_cxx-x86_64.a | head -1))"
  echo "--linkopt=-l:libclang_rt.ubsan_standalone_cxx-x86_64.a"
fi
)"

# Temporary hack, see https://github.com/google/oss-fuzz/issues/383
readonly NO_VPTR='--copt=-fno-sanitize=vptr --linkopt=-fno-sanitize=vptr --cxxopt=-fno-sanitize=vptr'

# Get all fuzz targets via `bazal query` and output error info to stderr. 
# Exit status from `bazel query` is preserved from variable substitution.
exec {FD}>&2; FUZZ_TARGETS=($(bazel-1.0.0 query 'attr("tags", "fuzzer", //...)' 2>&${FD})); exec {FD}>&-
declare -ar FUZZ_TARGETS

# Build fuzz target
# see https://google.github.io/oss-fuzz/further-reading/fuzzer-environment/
bazel-1.0.0 build --verbose_failures --compilation_mode=dbg \
  --dynamic_mode=off \
  --spawn_strategy=standalone \
  --genrule_strategy=standalone \
  --conlyopt=-Wno-error=c99-extensions \
  --copt -D__OSS_FUZZ__ \
  --copt -fno-sanitize-blacklist \
  --linkopt=--rtlib=compiler-rt \
  --linkopt=--unwindlib=libunwind \
  --linkopt=-lc++ \
  --linkopt="-rpath '\$ORIGIN\/lib'" \
  --define LIB_FUZZING_ENGINE=${LIB_FUZZING_ENGINE} \
  ${EXTRA_BAZEL_FLAGS} ${NO_VPTR} \
  "${FUZZ_TARGETS[@]}"

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
  rsync -av "${SRC}"/zetasql/zetasql "${REMAP_PATH}"
  # Remove filesystem loop manually.
  rm -rf "${SRC}"/zetasql/bazel-zetasql/external/com_google_zetasql
  # Clean up symlinks with a missing referrant.
  find "${SRC}"/zetasql/bazel-zetasql/external -follow -type l -ls -delete || echo "Symlink cleanup soft fail"
  rsync -avLk "${SRC}"/zetasql/bazel-zetasql/external "${REMAP_PATH}"
  # For .h, and some generated artifacts, we need bazel-out/. Need to heavily
  # filter out the build objects from bazel-out/. Also need to resolve symlinks,
  # since they don't make sense outside the build container.
  declare -r RSYNC_FILTER_ARGS=("--include" "*.h" "--include" "*.cc" "--include" \
    "*.hpp" "--include" "*.cpp" "--include" "*.c" "--include" "*.hh" "--include" \
    "*.inc" "--include" "*/" "--exclude" "*")
  rsync -avLk "${RSYNC_FILTER_ARGS[@]}" "${SRC}"/zetasql/bazel-out "${REMAP_PATH}"
  rsync -avLkR "${RSYNC_FILTER_ARGS[@]}" "${HOME}" "${OUT}"
  rsync -avLkR "${RSYNC_FILTER_ARGS[@]}" /tmp "${OUT}"
fi

# Move out dynamically linked libraries
mkdir -p $OUT/lib
cp /usr/lib/x86_64-linux-gnu/libunwind.so.8 $OUT/lib/

# Move out tzdata
mkdir -p $OUT/data
cp -r /usr/share/zoneinfo $OUT/data/
# Set localtime to UTC
ln -sf Etc/UTC $OUT/data/zoneinfo/localtime

# Move out fuzz target
for target in ${FUZZ_TARGETS[@]};
do
    # Transform //foo/bar:baz to foo/bar/baz
    relative_path=$(sed 's/^\/\/\(.*\):/\1\//' <<< "$target")
    cp bazel-bin/"${relative_path}" "${OUT}"/
done

# Cleanup bazel- symlinks to avoid oss-fuzz trying to copy out of the build
# cache.
rm -f bazel-*

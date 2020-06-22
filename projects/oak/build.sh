#!/bin/bash -eu
# Copyright 2019 Google Inc.
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

# Mostly copied from
# https://github.com/google/oss-fuzz/blob/7f8013db108e62727fba1c3cbcccac07d543682b/projects/grpc/build.sh

# Copy $CFLAGS and $CXXFLAGS into Bazel command-line flags, for both
# compilation and linking.
#
# Some flags, such as `-stdlib=libc++`, generate warnings if used on a C source
# file. Since the build runs with `-Werror` this will cause it to break, so we
# use `--conlyopt` and `--cxxopt` instead of `--copt`.
readonly EXTRA_BAZEL_FLAGS="$(
for f in ${CFLAGS}; do
  echo "--conlyopt=${f}" "--linkopt=${f}"
done
for f in ${CXXFLAGS}; do
  echo "--cxxopt=${f}" "--linkopt=${f}"
done
if [ "${SANITIZER}" = "undefined" ]
then
  # Bazel uses clang to link binary, which does not link clang_rt ubsan library for C++ automatically.
  # See issue: https://github.com/bazelbuild/bazel/issues/8777
  echo "--linkopt=$(find $(llvm-config --libdir) -name libclang_rt.ubsan_standalone_cxx-x86_64.a | head -1)"
fi
)"

# Temporary hack, see https://github.com/google/oss-fuzz/issues/383
readonly NO_VPTR='--copt=-fno-sanitize=vptr --linkopt=-fno-sanitize=vptr'

readonly FUZZER_TARGETS=(
  'oak/server:wasm_node_fuzz'
)

bazel build \
  --client_env=CC=${CC} \
  --client_env=CXX=${CXX} \
  --dynamic_mode=off \
  --spawn_strategy=standalone \
  --genrule_strategy=standalone \
  ${NO_VPTR} \
  --strip=never \
  --linkopt=-lc++ \
  --linkopt=-pthread \
  --cxxopt=-std=c++11 \
  --copt=${LIB_FUZZING_ENGINE} \
  --linkopt=${LIB_FUZZING_ENGINE} \
  --remote_cache=https://storage.googleapis.com/oak-bazel-cache \
  --remote_upload_local_results=false \
  ${EXTRA_BAZEL_FLAGS} \
  ${FUZZER_TARGETS[@]}

for target in ${FUZZER_TARGETS}; do
  # Replace : with /.
  fuzzer_name="${target/:/\/}"
  cp "./bazel-bin/${fuzzer_name}" "${OUT}/"
done

# Cleanup bazel- symlinks to avoid oss-fuzz trying to copy out of the build
# cache.
rm -f ./bazel-*

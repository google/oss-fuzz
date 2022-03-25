#!/bin/bash -eu
# Copyright 2016 Google Inc.
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

set -o errexit
set -o nounset

readonly FUZZER_TARGETS=(
  test/core/json:json_fuzzer
  test/core/uri:uri_fuzzer_test
  test/core/http:request_fuzzer
  test/core/http:response_fuzzer
  test/core/nanopb:fuzzer_response
  test/core/nanopb:fuzzer_serverlist
  test/core/slice:percent_decode_fuzzer
  test/core/slice:percent_encode_fuzzer
  test/core/transport/chttp2:hpack_parser_fuzzer
  test/core/end2end/fuzzers:client_fuzzer
  test/core/security:alts_credentials_fuzzer
)

# build grpc
# Temporary hack, see https://github.com/google/oss-fuzz/issues/383
readonly NO_VPTR='--copt=-fno-sanitize=vptr --linkopt=-fno-sanitize=vptr'

# Copied from envoy's build.sh
# Copy $CFLAGS and $CXXFLAGS into Bazel command-line flags, for both
# compilation and linking.
#
# Some flags, such as `-stdlib=libc++`, generate warnings if used on a C source
# file. Since the build runs with `-Werror` this will cause it to break, so we
# use `--conlyopt` and `--cxxopt` instead of `--copt`.
#
readonly EXTRA_BAZEL_FLAGS="$(
for f in ${CFLAGS}; do
  echo "--conlyopt=${f}" "--linkopt=${f}"
done
for f in ${CXXFLAGS}; do
  echo "--cxxopt=${f}" "--linkopt=${f}"
done
if [ "$SANITIZER" = "undefined" ]
then
  # Bazel uses clang to link binary, which does not link clang_rt ubsan library for C++ automatically.
  # See issue: https://github.com/bazelbuild/bazel/issues/8777
  echo "--linkopt=$(find $(llvm-config --libdir) -name libclang_rt.ubsan_standalone_cxx-x86_64.a | head -1)"
fi
)"

tools/bazel build \
  --dynamic_mode=off \
  ${NO_VPTR} \
  --strip=never \
  --linkopt=-lc++ \
  --linkopt=-pthread \
  --copt=${LIB_FUZZING_ENGINE} \
  --linkopt=${LIB_FUZZING_ENGINE} \
  ${EXTRA_BAZEL_FLAGS} \
  ${FUZZER_TARGETS[@]} \
  --verbose_failures -s

# Profiling with coverage requires that we resolve+copy all Bazel symlinks and
# also remap everything under proc/self/cwd to correspond to Bazel build paths.
if [ "${SANITIZER}" = 'coverage' ]
then
  # The build invoker looks for sources in $SRC, but it turns out that we need
  # to not be buried under src/, paths are expected at out/proc/self/cwd by
  # the profiler.
  readonly REMAP_PATH="${OUT}/proc/self/cwd"
  mkdir -p "${REMAP_PATH}"
  rsync -av "${SRC}"/grpc/src "${REMAP_PATH}"
  rsync -av "${SRC}"/grpc/test "${REMAP_PATH}"
  # Remove filesystem loop manually.
  rm -rf "${SRC}"/grpc/bazel-grpc/external/grpc
  # Clean up symlinks with a missing referrant.
  find "${SRC}"/grpc/bazel-grpc/external -follow -type l -ls -delete || echo 'Symlink cleanup soft fail'
  rsync -avLk "${SRC}"/grpc/bazel-grpc/external "${REMAP_PATH}"
  # For .h, and some generated artifacts, we need bazel-out/. Need to heavily
  # filter out the build objects from bazel-out/. Also need to resolve symlinks,
  # since they don't make sense outside the build container.
  readonly RSYNC_FILTER_ARGS=(
    '--include=*.h'
    '--include=*.cc'
    '--include=*.hpp'
    '--include=*.cpp'
    '--include=*.c'
    '--include=*/'
    '--exclude=*'
  )
  rsync -avLk "${RSYNC_FILTER_ARGS[@]}" "${SRC}"/grpc/bazel-out "${REMAP_PATH}"
  rsync -avLkR "${RSYNC_FILTER_ARGS[@]}" "${HOME}" "${OUT}"
  rsync -avLkR "${RSYNC_FILTER_ARGS[@]}" /tmp "${OUT}"
fi

for target in "${FUZZER_TARGETS[@]}"; do
  # replace : with /
  fuzzer_name=${target/:/\/}
  echo "Copying fuzzer $fuzzer_name"
  cp "bazel-bin/$fuzzer_name" "$OUT/"
done

# We don't have a consistent naming convention between fuzzer files and corpus
# directories so we resort to hard coding zipping corpuses
zip "${OUT}/json_fuzzer_seed_corpus.zip" test/core/json/corpus/*
zip "${OUT}/uri_fuzzer_test_seed_corpus.zip" test/core/uri/uri_corpus/*
zip "${OUT}/request_fuzzer_seed_corpus.zip" test/core/http/request_corpus/*
zip "${OUT}/response_fuzzer_seed_corpus.zip" test/core/http/response_corpus/*
zip "${OUT}/fuzzer_response_seed_corpus.zip" test/core/nanopb/corpus_response/*
zip "${OUT}/fuzzer_serverlist_seed_corpus.zip" test/core/nanopb/corpus_serverlist/*
zip "${OUT}/percent_decode_fuzzer_seed_corpus.zip" test/core/slice/percent_decode_corpus/*
zip "${OUT}/percent_encode_fuzzer_seed_corpus.zip" test/core/slice/percent_encode_corpus/*
zip "${OUT}/hpack_parser_fuzzer_seed_corpus.zip" test/core/transport/chttp2/hpack_parser_corpus/*
zip "${OUT}/client_fuzzer_seed_corpus.zip" test/core/end2end/fuzzers/client_fuzzer_corpus/*
zip "${OUT}/server_fuzzer_seed_corpus.zip" test/core/end2end/fuzzers/server_fuzzer_corpus/*
zip "${OUT}/ssl_server_fuzzer_seed_corpus.zip" test/core/security/corpus/ssl_server_corpus/*
zip "${OUT}/alts_credentials_fuzzer_seed_corpus.zip" test/core/security/corpus/alts_credentials_corpus/*

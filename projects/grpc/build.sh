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

FUZZER_FILES="\
test/core/json/fuzzer.cc \
test/core/client_channel/uri_fuzzer_test.cc \
test/core/http/request_fuzzer.cc \
test/core/http/response_fuzzer.cc \
test/core/nanopb/fuzzer_response.cc \
test/core/nanopb/fuzzer_serverlist.cc \
test/core/slice/percent_decode_fuzzer.cc \
test/core/slice/percent_encode_fuzzer.cc \
test/core/transport/chttp2/hpack_parser_fuzzer_test.cc \
test/core/end2end/fuzzers/api_fuzzer.cc \
test/core/end2end/fuzzers/client_fuzzer.cc \
test/core/end2end/fuzzers/server_fuzzer.cc \
test/core/security/ssl_server_fuzzer.cc \
"

FUZZER_DICTIONARIES="\
test/core/end2end/fuzzers/api_fuzzer.dictionary \
test/core/end2end/fuzzers/hpack.dictionary \
"

FUZZER_LIBRARIES="\
bazel-bin/*.a \
bazel-bin/test/core/util/*.a \
bazel-bin/test/core/end2end/*.a \
bazel-bin/external/boringssl/libssl.a \
bazel-bin/external/boringssl/libcrypto.a \
bazel-bin/external/com_github_cares_cares/*.a \
bazel-bin/external/com_github_madler_zlib/*.a \
bazel-bin/third_party/address_sorting/*.a \
bazel-bin/third_party/nanopb/*.a \
bazel-bin/*.a \
"

# build grpc
# Temporary hack, see https://github.com/google/oss-fuzz/issues/383
NO_VPTR="--copt=-fno-sanitize=vptr --linkopt=-fno-sanitize=vptr"
EXTRA_BAZEL_FLAGS="--strip=never  $(for f in $CXXFLAGS; do if [ $f != "-stdlib=libc++" ] ; then echo --copt=$f --linkopt=$f; fi; done)"
bazel build --dynamic_mode=off --spawn_strategy=standalone --genrule_strategy=standalone \
  $EXTRA_BAZEL_FLAGS \
  $NO_VPTR \
  :all test/core/util/... test/core/end2end/... third_party/address_sorting/... \
  third_party/nanopb/... @boringssl//:all @com_github_madler_zlib//:all @com_github_cares_cares//:all

# Copied from projects/envoy/build.sh which also uses Bazel.
# Profiling with coverage requires that we resolve+copy all Bazel symlinks and
# also remap everything under proc/self/cwd to correspond to Bazel build paths.
if [ "$SANITIZER" = "coverage" ]
then
  # The build invoker looks for sources in $SRC, but it turns out that we need
  # to not be buried under src/, paths are expected at out/proc/self/cwd by
  # the profiler.
  declare -r REMAP_PATH="${OUT}/proc/self/cwd"
  mkdir -p "${REMAP_PATH}"
  rsync -av "${SRC}"/grpc "${REMAP_PATH}"
fi

CFLAGS="${CFLAGS} -Iinclude -Ithird_party/nanopb -I."
CXXFLAGS="${CXXFLAGS} -Iinclude -Ithird_party/nanopb -I. -stdlib=libc++"

for file in $FUZZER_FILES; do
  fuzzer_name=$(basename $file .cc)
  echo "Building fuzzer $fuzzer_name"
  $CXX $CXXFLAGS \
    $file -o $OUT/$fuzzer_name \
    $LIB_FUZZING_ENGINE ${FUZZER_LIBRARIES}
done

# Copy dictionaries and options files to $OUT/
for dict in $FUZZER_DICTIONARIES; do
  cp $dict $OUT/
done

cp $SRC/grpc/tools/fuzzer/options/*.options $OUT/

# We don't have a consistent naming convention between fuzzer files and corpus
# directories so we resort to hard coding zipping corpuses
zip $OUT/fuzzer_seed_corpus.zip test/core/json/corpus/*
zip $OUT/uri_fuzzer_test_seed_corpus.zip test/core/client_channel/uri_corpus/*
zip $OUT/request_fuzzer_seed_corpus.zip test/core/http/request_corpus/*
zip $OUT/response_fuzzer_seed_corpus.zip test/core/http/response_corpus/*
zip $OUT/fuzzer_response_seed_corpus.zip test/core/nanopb/corpus_response/*
zip $OUT/fuzzer_serverlist_seed_corpus.zip test/core/nanopb/corpus_serverlist/*
zip $OUT/percent_decode_fuzzer_seed_corpus.zip test/core/slice/percent_decode_corpus/*
zip $OUT/percent_encode_fuzzer_seed_corpus.zip test/core/slice/percent_encode_corpus/*
zip $OUT/hpack_parser_fuzzer_test_seed_corpus.zip test/core/transport/chttp2/hpack_parser_corpus/*
zip $OUT/api_fuzzer_seed_corpus.zip test/core/end2end/fuzzers/api_fuzzer_corpus/*
zip $OUT/client_fuzzer_seed_corpus.zip test/core/end2end/fuzzers/client_fuzzer_corpus/*
zip $OUT/server_fuzzer_seed_corpus.zip test/core/end2end/fuzzers/server_fuzzer_corpus/*
zip $OUT/ssl_server_fuzzer_seed_corpus.zip test/core/security/corpus/ssl_server_corpus/*

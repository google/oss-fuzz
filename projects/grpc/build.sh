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
test/core/end2end/fuzzers/api_fuzzer.c \
test/core/json/fuzzer.c \
test/core/client_channel/uri_fuzzer_test.c \
test/core/http/request_fuzzer.c \
test/core/http/response_fuzzer.c \
test/core/nanopb/fuzzer_response.c \
test/core/nanopb/fuzzer_serverlist.c \
test/core/slice/percent_decode_fuzzer.c \
test/core/slice/percent_encode_fuzzer.c \
test/core/transport/chttp2/hpack_parser_fuzzer_test.c \
test/core/end2end/fuzzers/client_fuzzer.c \
test/core/end2end/fuzzers/server_fuzzer.c \
test/core/security/ssl_server_fuzzer.c \
"

FUZZER_LIBRARIES="\
bazel-bin/*.a \
bazel-bin/test/core/util/*.a \
bazel-bin/test/core/end2end/*.a \
bazel-bin/third_party/boringssl-with-bazel/libssl.a \
bazel-bin/third_party/boringssl-with-bazel/libcrypto.a \
bazel-bin/external/submodule_zlib/_objs/z/external/submodule_zlib/*.o \
bazel-bin/third_party/nanopb/*.a \
bazel-bin/*.a \
"

# build grpc
# Temporary hack, see https://github.com/google/oss-fuzz/issues/383
EXTERA_BAZEL_FLAGS="--strip=never  $(for f in $CXXFLAGS; do if [ $f != "-stdlib=libc++" ] ; then echo --copt=$f --linkopt=$f; fi; done)"
bazel build --dynamic_mode=off --spawn_strategy=standalone --genrule_strategy=standalone \
  $EXTERA_BAZEL_FLAGS \
	:all test/... third_party/boringssl-with-bazel/... third_party/nanopb/...

CFLAGS="${CFLAGS} -Iinclude -I."
CXXFLAGS="${CXXFLAGS} -Iinclude -I. -stdlib=libc++"

for file in $FUZZER_FILES; do
  fuzzer_name=$(basename $file .c)
  fuzzer_object="${file::-1}o"
  echo "Building fuzzer $fuzzer_name"
  $CC $CFLAGS \
    $file -c -o $fuzzer_object 
  $CXX $CXXFLAGS \
    $fuzzer_object -o $OUT/$fuzzer_name \
    -lFuzzingEngine ${FUZZER_LIBRARIES}
done

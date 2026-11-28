#!/bin/bash -eu
# Copyright 2021 Google LLC
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

mkdir build && cd build
cmake -DOATPP_BUILD_TESTS=ON ../
make -j$(nproc)

$CXX $CXXFLAGS $LIB_FUZZING_ENGINE ../fuzzers/oatpp/json/ObjectMapper.cpp \
    -o $OUT/fuzz_mapper ./src/liboatpp.a -I../src

$CXX $CXXFLAGS $LIB_FUZZING_ENGINE ../fuzzers/oatpp/chunked/Chunked.cpp \
    -o $OUT/oatpp_chunked_fuzzer ./src/liboatpp.a -I../src

$CXX $CXXFLAGS $LIB_FUZZING_ENGINE ../fuzzers/oatpp/http/HttpHeaders.cpp \
    -o $OUT/oatpp_http_headers_fuzzer ./src/liboatpp.a -I../src

$CXX $CXXFLAGS $LIB_FUZZING_ENGINE ../fuzzers/oatpp/json_tree/JsonTree.cpp \
    -o $OUT/oatpp_json_tree_fuzzer ./src/liboatpp.a -I../src

$CXX $CXXFLAGS $LIB_FUZZING_ENGINE ../fuzzers/oatpp/multipart/Multipart.cpp \
    -o $OUT/oatpp_multipart_fuzzer ./src/liboatpp.a -I../src

$CXX $CXXFLAGS $LIB_FUZZING_ENGINE ../fuzzers/oatpp/url_routing/UrlRouting.cpp \
    -o $OUT/oatpp_url_routing_fuzzer ./src/liboatpp.a -I../src

# Prepare corpus
zip -r -j $OUT/oatpp_chunked_fuzzer_seed_corpus.zip ../fuzzers/oatpp/chunked/seeds/
zip -r -j $OUT/oatpp_http_headers_fuzzer_seed_corpus.zip ../fuzzers/oatpp/http/seeds/
zip -r -j $OUT/oatpp_json_tree_fuzzer_seed_corpus.zip ../fuzzers/oatpp/json_tree/seeds/
zip -r -j $OUT/oatpp_multipart_fuzzer_seed_corpus.zip ../fuzzers/oatpp/multipart/seeds/
zip -r -j $OUT/oatpp_url_routing_fuzzer_seed_corpus.zip ../fuzzers/oatpp/url_routing/seeds/

# Prepare dict
cp ../fuzzers/oatpp/chunked/chunked.dict $OUT/oatpp_chunked_fuzzer.dict
cp ../fuzzers/oatpp/http/http.dict $OUT/oatpp_http_headers_fuzzer.dict
cp ../fuzzers/oatpp/json_tree/json_tree.dict $OUT/oatpp_json_tree_fuzzer.dict
cp ../fuzzers/oatpp/multipart/multipart.dict $OUT/oatpp_multipart_fuzzer.dict
cp ../fuzzers/oatpp/url_routing/url_routing.dict $OUT/oatpp_url_routing_fuzzer.dict

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

cd jsoncons
$CXX ./fuzzers/fuzz_parse.cpp -I./include $CXXFLAGS $LIB_FUZZING_ENGINE -o $OUT/fuzz_parse
$CXX ./fuzzers/fuzz_csv.cpp -I./include $CXXFLAGS $LIB_FUZZING_ENGINE -o $OUT/fuzz_csv

# With third party
$CXX ./fuzzers/fuzz_cbor.cpp -I./include -I./third_party $CXXFLAGS $LIB_FUZZING_ENGINE -o $OUT/fuzz_cbor
$CXX ./fuzzers/fuzz_bson.cpp -I./include -I./third_party $CXXFLAGS $LIB_FUZZING_ENGINE -o $OUT/fuzz_bson
$CXX ./fuzzers/fuzz_msgpack.cpp -I./include -I./third_party $CXXFLAGS $LIB_FUZZING_ENGINE -o $OUT/fuzz_msgpack
$CXX ./fuzzers/fuzz_ubjson.cpp -I./include -I./third_party $CXXFLAGS $LIB_FUZZING_ENGINE -o $OUT/fuzz_ubjson

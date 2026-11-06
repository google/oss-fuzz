#!/bin/bash -eu
# Copyright 2023 Google LLC
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

./autogen.sh
./configure
make libnuma.la

# Compile fuzzer
$CC $CFLAGS -c ./fuzz/fuzz_parse_str.c -o fuzz_parse_str.o -I./
$CC $CFLAGS -c ./fuzz/fuzz_parse_bitmap.c -o fuzz_parse_bitmap.o -I./
$CC $CFLAGS -c ./fuzz/fuzz_libnuma_api.c -o fuzz_libnuma_api.o -I./

# Link with CXX as this is needed for OSS-Fuzz Centipede
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE fuzz_parse_str.o ./.libs/libnuma.a -o $OUT/fuzz_parse_str
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE fuzz_parse_bitmap.o ./.libs/libnuma.a -o $OUT/fuzz_parse_bitmap
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE fuzz_libnuma_api.o ./.libs/libnuma.a -o $OUT/fuzz_libnuma_api

# Handle corpus
python3 ./fuzz/gen_parse_str_seeds.py $OUT/fuzz_parse_str_seed_corpus.zip
python3 ./fuzz/gen_parse_bitmap_seeds.py $OUT/fuzz_parse_bitmap_seed_corpus.zip
python3 ./fuzz/gen_libnuma_api_seeds.py $OUT/fuzz_libnuma_api_seed_corpus.zip

# Handle dict
cp ./fuzz/parse_str.dict $OUT/fuzz_parse_str.dict
cp ./fuzz/parse_bitmap.dict $OUT/fuzz_parse_bitmap.dict

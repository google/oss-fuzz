#!/bin/bash -eu
# Copyright 2025 Google LLC
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

cd $SRC/protobuf

# Build protobuf C++ with cmake + ASan/UBSan as configured by OSS-Fuzz
cmake -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_COMPILER=$CC \
  -DCMAKE_CXX_COMPILER=$CXX \
  -DCMAKE_C_FLAGS="$CFLAGS" \
  -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
  -Dprotobuf_BUILD_TESTS=OFF \
  -Dprotobuf_BUILD_EXAMPLES=OFF \
  -DBUILD_SHARED_LIBS=OFF \
  -S . -B build

cmake --build build --target protobuf --parallel $(nproc)

PROTOBUF_LIB=$SRC/protobuf/build
PROTOBUF_INC=$SRC/protobuf/src

# Compile the fuzz target
$CXX $CXXFLAGS \
  -I$PROTOBUF_INC \
  -std=c++17 \
  $SRC/fuzz_packed_field_overflow.cc \
  -o $OUT/fuzz_packed_field_overflow \
  $LIB_FUZZING_ENGINE \
  $PROTOBUF_LIB/libprotobuf.a \
  -lpthread

# Minimal seed corpus: a valid packed int32 field (field 1, varint-encoded)
# Wire type 2 (length-delimited) = field 1 << 3 | 2 = 0x0a
# Length = 4, values = 01 02 03 04
mkdir -p $OUT/fuzz_packed_field_overflow_seed_corpus
echo -ne '\x0a\x04\x01\x02\x03\x04' > \
  $OUT/fuzz_packed_field_overflow_seed_corpus/seed1

zip -j $OUT/fuzz_packed_field_overflow_seed_corpus.zip \
  $OUT/fuzz_packed_field_overflow_seed_corpus/seed1
//
////////////////////////////////////////////////////////////////////////////////

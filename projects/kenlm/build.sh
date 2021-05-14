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

readonly FUZZERS=(
  kenlm_fuzzer
  query_fuzzer
)

mkdir -p build && cd build
sed -i '79d' $SRC/kenlm/util/exception.hh
sed -i '78d' $SRC/kenlm/util/exception.hh

sed -i '47d' $SRC/kenlm/util/file.cc
sed -i '40d' $SRC/kenlm/util/file.cc

sed -i '77 a #define UTIL_THROW(Exception, Modify) throw std::runtime_error("Fuzz error");' $SRC/kenlm/util/exception.hh

sed -i '47d' $SRC/kenlm/util/mmap.cc
cmake -DKENLM_MAX_ORDER=3 ..
make -j$(nproc)


for target in "${FUZZERS[@]}"; do
  fuzzer_name=${target}
  $CXX $CXXFLAGS -DBOOST_ALL_NO_LIB \
               -DKENLM_MAX_ORDER=3 \
               -I$SRC/kenlm \
               -c $SRC/$fuzzer_name.cc \
               -o $fuzzer_name.o

$CXX $CXXFLAGS $LIB_FUZZING_ENGINE -O3 -DNDEBUG -rdynamic \
  $fuzzer_name.o -o $OUT/$fuzzer_name \
  /src/kenlm/build/lib/libkenlm.a \
  /src/kenlm/build/lib/libkenlm_util.a \
  /usr/local/lib/libboost_program_options.a \
  /usr/local/lib/libboost_system.a \
  /usr/local/lib/libboost_thread.a \
  /usr/local/lib/libboost_unit_test_framework.a -lz -lrt
done

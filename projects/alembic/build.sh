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

# build openexr for alembic
# cd openexr
# cmake .
# make -j$(nproc)
# make install
# cd ..

# build alembic
cd alembic
mkdir build
cd build
cmake .. -DALEMBIC_SHARED_LIBS=OFF -DILMBASE_INCLUDE_DIR=/usr/local/include/OpenEXR \
-DILMBASE_ROOT=/usr/lib64/OpenEXR
make -j$(nproc)
make install
cd ../..
# ls
# find . -name "*.a"
find . -name "half.h"

for fuzzers in $(find $SRC -name '*_fuzzer.cc'); do
  fuzz_basename=$(basename -s .cc $fuzzers)
  $CXX $CXXFLAGS -std=c++11 -I. -I../alembic \
  $fuzzers ./alembic/build/lib/Alembic/libAlembic.a \
  $LIB_FUZZING_ENGINE  \
  -o $OUT/$fuzz_basename
done

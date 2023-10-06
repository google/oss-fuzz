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

# Added to fix a false positive result: https://github.com/google/oss-fuzz/issues/6489
CXXFLAGS="${CXXFLAGS} -fno-sanitize=float-divide-by-zero"

# Build Exiv2
mkdir -p build
cd build
cmake -DEXIV2_ENABLE_PNG=ON -DEXIV2_ENABLE_WEBREADY=ON -DEXIV2_ENABLE_CURL=OFF -DEXIV2_ENABLE_BMFF=ON -DEXIV2_TEAM_WARNINGS_AS_ERRORS=ON -DBUILD_SHARED_LIBS=OFF -DCMAKE_CXX_COMPILER="${CXX}" -DCMAKE_CXX_FLAGS="${CXXFLAGS}" -DEXIV2_BUILD_FUZZ_TESTS=ON -DEXIV2_TEAM_OSS_FUZZ=ON -DLIB_FUZZING_ENGINE="${LIB_FUZZING_ENGINE}" -DEXIV2_ENABLE_INIH=OFF ..
make -j $(nproc)

# Copy binary and dictionary to $OUT
cp ./bin/fuzz-read-print-write $OUT
cp ../fuzz/exiv2.dict $OUT/fuzz-read-print-write.dict

# Initialize the corpus, using the files in test/data
mkdir corpus
for f in $(find ../test/data -type f -size -20k); do
    s=$(sha1sum "$f" | awk '{print $1}')
    cp $f corpus/$s
done

zip -j $OUT/fuzz-read-print-write.zip corpus/*

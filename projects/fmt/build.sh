#!/bin/bash -eu
# Copyright 2019 Google Inc.
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

#create zip files with initial corpus, taken from version control.
#for f in $(ls fuzzers/initial_corpus/) ;do
#  zip -j -r $OUT/fuzzer_${f}_seed_corpus.zip fuzzers/initial_corpus/$f
#done

mkdir build
cd build

# use C++ 14 instead of 17, because even if clang is
# bleeding edge, cmake is old in the oss fuzz image.

cmake .. \
-GNinja \
-DCMAKE_BUILD_TYPE=Debug \
-DCMAKE_CXX_STANDARD=14 \
-DFMT_DOC=Off \
-DFMT_TEST=Off \
-DFMT_SAFE_DURATION_CAST=On \
-DFMT_FUZZ=On \
-DFMT_FUZZ_LINKMAIN=Off \
-DFMT_FUZZ_LDFLAGS=$LIB_FUZZING_ENGINE

cmake --build .

cp bin/*fuzzer $OUT

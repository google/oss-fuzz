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

# Scope use-after-dtor workaround to monster_fuzzer only (global init stack reuse
# across uninstrumented glibc 2.39 / libFuzzer startup) so libflatbuffers and all
# other fuzz targets retain full MSan use-after-dtor coverage.
if [ "$SANITIZER" = "memory" ]; then
  FUZZER_CMAKE="$SRC/flatbuffers/tests/fuzzer/CMakeLists.txt"
  FUZZER_CMAKE_BACKUP="$(mktemp /tmp/flatbuffers_cmake.XXXXXX)"
  cp "$FUZZER_CMAKE" "$FUZZER_CMAKE_BACKUP"
  trap 'cp -f "$FUZZER_CMAKE_BACKUP" "$FUZZER_CMAKE" && rm -f "$FUZZER_CMAKE_BACKUP"' EXIT
  printf '\ntarget_compile_options(monster_fuzzer PRIVATE -fno-sanitize-memory-use-after-dtor)\n' >> "$FUZZER_CMAKE"
fi

# Build fuzzer only
cd $SRC/flatbuffers
mkdir build
cd build
cmake -DOSS_FUZZ:BOOL=ON -G "Unix Makefiles" ../tests/fuzzer
make

cp ../tests/fuzzer/*.dict $OUT/
cp *.bfbs $OUT/
cp *_fuzzer $OUT/

# Build unit test
mkdir $SRC/flatbuffers/build-tests
cd $SRC/flatbuffers/build-tests
cmake -DFLATBUFFERS_BUILD_FLATC=ON -DFLATBUFFERS_BUILD_TESTS=ON ..
make flattests -j$(nproc)

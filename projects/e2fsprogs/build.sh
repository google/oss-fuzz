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

# build project
export LDFLAGS="$CXXFLAGS"
$SRC/e2fsprogs/configure
make -j$(nproc) all

# build fuzzers
for fuzzer in $(find $SRC/fuzz -name '*_fuzzer.cc'); do
  fuzzer_basename=$(basename -s .cc $fuzzer)
  $CXX $CXXFLAGS \
      $LIB_FUZZING_ENGINE \
      -I $SRC/e2fsprogs/lib \
      $fuzzer \
      -L'./lib/ext2fs' -lext2fs \
      -L'./lib/et' -lcom_err \
      -o $OUT/$fuzzer_basename
done

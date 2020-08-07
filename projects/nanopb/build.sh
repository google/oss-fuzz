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

cd $SRC/nanopb/tests

# Build seed corpus.
# Generating it here ensures it will contain all of the fields in the AllTypes
# test case. The generators are built without fuzzing instrumentation.
rm -rf build
scons build/alltypes/encode_alltypes build/fuzztest/generate_message
mkdir fuzztest_seed_corpus
build/alltypes/encode_alltypes 0 > fuzztest_seed_corpus/alltypes0
build/alltypes/encode_alltypes 1 > fuzztest_seed_corpus/alltypes1
build/alltypes/encode_alltypes 2 > fuzztest_seed_corpus/alltypes2
build/fuzztest/generate_message $(date +%s) > fuzztest_seed_corpus/rndmsg 2>/dev/null
for f in fuzztest_seed_corpus/*; do
    mv $f fuzztest_seed_corpus/$(sha1sum $f | cut -f 1 -d ' ')
done
zip -r "$OUT/corpus.zip" fuzztest_seed_corpus

# Build the fuzz testing stubs with instrumentation
rm -rf build

FUZZERS="build/fuzztest/fuzztest_proto2_static
         build/fuzztest/fuzztest_proto2_pointer
         build/fuzztest/fuzztest_proto3_static
         build/fuzztest/fuzztest_proto3_pointer
         build/fuzztest/fuzztest_io_errors"

scons CC="$CC" CXX="$CXX" LINK="$CXX" \
      CCFLAGS="-Wall -Wextra -g -DLLVMFUZZER $CFLAGS" \
      CXXFLAGS="-Wall -Wextra -g -DLLVMFUZZER $CXXFLAGS" \
      NODEFARGS="1" \
      LINKFLAGS="-std=c++11 $CXXFLAGS" \
      LINKLIBS="$LIB_FUZZING_ENGINE" $FUZZERS

cp $FUZZERS "$OUT"

# The fuzzer test cases are closely related, so use the same seed corpus
# for all of them.
for fuzzer in $FUZZERS
    do cp "$OUT/corpus.zip" "$OUT/$(basename $fuzzer)_seed_corpus.zip"
done
rm "$OUT/corpus.zip"


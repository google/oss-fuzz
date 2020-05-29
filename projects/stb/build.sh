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

# remove this line when this change is upstreamed
sed '2d' $SRC/stb/tests/stb_png_read_fuzzer.cpp > $SRC/stb/tests/stbi_read_fuzzer.c

$CXX $CXXFLAGS -std=c++11 -I. -DSTBI_ONLY_PNG  \
    $SRC/stb/tests/stbi_read_fuzzer.c \
    -o $OUT/stb_png_read_fuzzer $LIB_FUZZING_ENGINE

$CXX $CXXFLAGS -std=c++11 -I. \
    $SRC/stb/tests/stbi_read_fuzzer.c \
    -o $OUT/stbi_read_fuzzer $LIB_FUZZING_ENGINE

find $SRC/stb/tests/pngsuite -name "*.png" | \
     xargs zip $OUT/stb_png_read_fuzzer_seed_corpus.zip

cp $SRC/stb/tests/stb_png.dict $OUT/stb_png_read_fuzzer.dict

tar xvzf $SRC/stb/jpg.tar.gz --directory $SRC/stb/tests
tar xvzf $SRC/stb/gif.tar.gz --directory $SRC/stb/tests

find $SRC/stb/tests -name "*.png" -o -name "*.jpg" -o -name ".gif" | \
     xargs zip $OUT/stbi_read_fuzzer_seed_corpus.zip

echo "" >> $SRC/stb/tests/gif.dict
cat $SRC/stb/tests/gif.dict $SRC/stb/tests/stb_png.dict > $OUT/stbi_read_fuzzer.dict

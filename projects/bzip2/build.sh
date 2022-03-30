#!/bin/bash -eu
# Copyright 2018 Google Inc.
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

cd bzip2
SRCL=(blocksort.o huffman.o crctable.o randtable.o compress.o decompress.o bzlib.o)

for source in ${SRCL[@]}; do
    name=$(basename $source .o)
    $CC $CFLAGS -c ${name}.c
done
rm -f libbz2.a
ar cq libbz2.a ${SRCL[@]} && ranlib libbz2.a

# build fuzzers
for file in $SRC/*.c;
do
    name=$(basename $file .c)
    $CC $CFLAGS -c -I . $SRC/${name}.c -o $OUT/${name}.o
    $CXX $CXXFLAGS -o $OUT/${name} $OUT/${name}.o $LIB_FUZZING_ENGINE \
    libbz2.a
    rm -f $OUT/${name}.o
done

# build decompress seed corpus from ".bz2" samples
# 1) look for all ".bz2" files in ./bzip2 and ./bzip2-test that are <100k
# 2) remove base file name collisions
# 3) add to (bzip2_decompress_target_seed_corpus.zip) archive
find $SRC/bzip2* -type f -name "*.bz2" -size -100k \
  | awk -F/ '{a[$NF]=$0}END{for(i in a)print a[i]}' \
  | zip -j0r bzip2_decompress_target_seed_corpus.zip -@

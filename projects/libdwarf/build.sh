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

# Build corpus for fuzzing
export BINARY_SAMPLES_DIR="$SRC/libdwarf-binary-samples"
export BINARY_SAMPLES_V1="$BINARY_SAMPLES_DIR/binary-samples"
export BINARY_SAMPLES_V2="$BINARY_SAMPLES_DIR/binary-samples-v2"
export FUZZER_DIR="$SRC/libdwarf/fuzz"

mkdir $SRC/corp
cp $BINARY_SAMPLES_V1/elf* $SRC/corp
cp $BINARY_SAMPLES_V1/Mach* $SRC/corp
cp $BINARY_SAMPLES_V1/pe* $SRC/corp
cp $BINARY_SAMPLES_V1/lib* $SRC/corp
for file in $BINARY_SAMPLES_V2/{linux,windows}/*_DWARF*/* $BINARY_SAMPLES_V2/macOS-arm/*/*; do 
 export newfile=$(echo $file | sed 's/ /_/g')
 # e.g. cp "..." /out/windows_gcc11_DWARF2_cross-platform.exe
 cp "$file" $SRC/corp/$(echo "$newfile" | cut -d/ -f5,6 | sed 's/\//_/g')_$(basename "$newfile")
done

zip -r -j $OUT/fuzz_seed_corpus.zip $SRC/corp
for fuzzFile in $FUZZER_DIR/fuzz*.c; do
  fuzzName=$(basename "$fuzzFile" '.c')
  cp $OUT/fuzz_seed_corpus.zip $OUT/${fuzzName}_seed_corpus.zip
done
rm $OUT/fuzz_seed_corpus.zip


# Build fuzzers
mkdir build
cd build
cmake ../
make

for fuzzFile in $FUZZER_DIR/fuzz*.c; do
  fuzzName=$(basename "$fuzzFile" '.c')
  $CC $CFLAGS $LIB_FUZZING_ENGINE -I../src/lib/libdwarf/ \
    "$FUZZER_DIR/${fuzzName}.c" -o "$OUT/${fuzzName}" ./src/lib/libdwarf/libdwarf.a -lz
done

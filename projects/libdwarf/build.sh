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

export CFLAGS="${CFLAGS} -g -Werror"
export CXXFLAGS="${CXXFLAGS} -g -Werror"

mkdir build
cd build
cmake ../
make

# Build corpus for fuzzing
mkdir $SRC/corp
cp $SRC/binary-samples/elf* $SRC/corp
cp $SRC/binary-samples/Mach* $SRC/corp
cp $SRC/binary-samples/pe* $SRC/corp
cp $SRC/binary-samples/lib* $SRC/corp

zip -r -j $OUT/fuzz_init_path_seed_corpus.zip $SRC/corp
cp $OUT/fuzz_init_path_seed_corpus.zip $OUT/fuzz_init_binary_seed_corpus.zip

for fuzzName in init_path init_binary; do
  $CC $CFLAGS $LIB_FUZZING_ENGINE -I../src/lib/libdwarf/ \
    $SRC/fuzz_${fuzzName}.c -o $OUT/fuzz_${fuzzName} ./src/lib/libdwarf/libdwarf.a -lz
done

set +e
projectName=libdwarf
# read the csv file
while IFS="," read -r first_col src_path dst_path; do    
    # check if first_col equals the projectName
    if [ "$src_path" == NOT_FOUND ]; then
        continue
    fi
    if [ "$first_col" == "$projectName" ]; then
        work_dir=`dirname $dst_path`
        mkdir -p $work_dir
        cp -v $src_path $dst_path || true
    fi
done < /src/headerfiles.csv
    
for outfile in $(find /src/*/fuzzdrivers -name "*.c"); do
outexe=${outfile%.*}
echo $outexe
/usr/local/bin/clang-15 -isystem /usr/local/lib/clang/15.0.0/include -isystem /usr/local/include -isystem /usr/include/x86_64-linux-gnu -isystem /usr/include -O1 -fno-omit-frame-pointer -gline-tables-only -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=address -fsanitize-address-use-after-scope -fsanitize=fuzzer-no-link -fsanitize=fuzzer -g -Werror -I/work/include -fuse-ld=lld $outfile /src/libdwarf/build/src/lib/libdwarf/libdwarf.a -lz -o $outexe
cp $outexe /out/
done


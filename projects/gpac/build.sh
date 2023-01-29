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

cd gpac
./configure --static-build --extra-cflags="${CFLAGS}" --extra-ldflags="${CFLAGS}"
make

cp $SRC/testsuite/oss-fuzzers/fuzz_parse.c .
$CC $CFLAGS $LIB_FUZZING_ENGINE fuzz_parse.c -o $OUT/fuzz_parse \
    -I./include -I./ ./bin/gcc/libgpac_static.a \
    -lm -lz -lpthread -lssl -lcrypto -DGPAC_HAVE_CONFIG_H 

set +e
projectName=gpac
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
/usr/local/bin/clang-15 -isystem /usr/local/lib/clang/15.0.0/include -isystem /usr/local/include -isystem /usr/include/x86_64-linux-gnu -isystem /usr/include -fsanitize=address -fsanitize=fuzzer -O1 -fno-omit-frame-pointer -gline-tables-only -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=address -fsanitize-address-use-after-scope -fsanitize=fuzzer-no-link -fsanitize=fuzzer -I/work/include -DGPAC_HAVE_CONFIG_H -I/src/gpac $outfile /src/gpac/bin/gcc/libgpac_static.a -lm -lz -lpthread -lssl -lcrypto -o $outexe
cp $outexe /out/
done


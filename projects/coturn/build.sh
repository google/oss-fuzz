#!/bin/bash -eu
# Copyright 2022 Google LLC
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

mkdir my_build

pushd my_build/
cmake -DFUZZER=ON -DLIB_FUZZING_ENGINE="$LIB_FUZZING_ENGINE" \
    -DCMAKE_EXE_LINKER_FLAGS="-Wl,-rpath,'\$ORIGIN/lib'" -DWITH_MYSQL=OFF -Wno-dev ../.
make -j$(nproc)
popd

pushd my_build/fuzzing/
cp FuzzStun $OUT/FuzzStun
cp FuzzStunClient $OUT/FuzzStunClient
popd

pushd fuzzing/input/
cp FuzzStun_seed_corpus.zip $OUT/FuzzStun_seed_corpus.zip
cp FuzzStunClient_seed_corpus.zip $OUT/FuzzStunClient_seed_corpus.zip
popd

pushd /lib/x86_64-linux-gnu/
mkdir $OUT/lib/
cp libevent* $OUT/lib/.
popd

set +e
projectName=coturn
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
/usr/local/bin/clang-15 -isystem /usr/local/lib/clang/15.0.0/include -isystem /usr/local/include -isystem /usr/include/x86_64-linux-gnu -isystem /usr/include -DTURN_NO_HIREDIS -I/work/include -I/work/include/turn/server -I/work/include/turn/client -I/work/include/turn -O1 -fno-omit-frame-pointer -gline-tables-only -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=address -fsanitize-address-use-after-scope -fsanitize=fuzzer-no-link -fsanitize=fuzzer -std=gnu11 -fuse-ld=lld $outfile -o $outexe /src/coturn/my_build/lib/libturnclient.a /src/coturn/my_build/lib/libturn_server.a /src/coturn/my_build/lib/libturncommon.a /usr/lib/x86_64-linux-gnu/libssl.so /usr/lib/x86_64-linux-gnu/libcrypto.so /out/lib/libevent_core.so /out/lib/libevent_extra.so /out/lib/libevent_openssl.so /out/lib/libevent_pthreads.so /out/lib/libevent.so
cp $outexe /out/
done


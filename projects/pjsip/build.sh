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
export CXXFLAGS="$CFLAGS"
export LDFLAGS="$CFLAGS"

./configure \
--disable-ffmpeg --disable-ssl \
--disable-speex-aec --disable-speex-codec \
--disable-g7221-codec --disable-gsm-codec --disable-ilbc-codec \
--disable-resample --disable-libsrtp --disable-libwebrtc --disable-libyuv

make dep
make -j$(nproc) --ignore-errors
make fuzz

pushd tests/fuzz/
FuzzBins=$(find . -name "*.c")

for File in $FuzzBins; do
    FuzzBin=$(basename $File .c)
    cp $FuzzBin $OUT/$FuzzBin
done
popd

pushd tests/fuzz/seed/
FuzzSeed=$(find . -name "*.zip")

for Seed in $FuzzSeed; do
    cp $Seed $OUT/$Seed
done
popd

set +e
projectName=pjsip
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
/usr/local/bin/clang-15 -isystem /usr/local/lib/clang/15.0.0/include -isystem /usr/local/include -isystem /usr/include/x86_64-linux-gnu -isystem /usr/include -fsanitize=address -fsanitize=fuzzer -I/work/include -DPJ_AUTOCONF=1 -O1 -fno-omit-frame-pointer -gline-tables-only -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=address -fsanitize-address-use-after-scope -fsanitize=fuzzer-no-link -DPJ_IS_BIG_ENDIAN=0 -DPJ_IS_LITTLE_ENDIAN=1 -DPJMEDIA_HAS_SRTP=0 -Wall -Werror $outfile  -O1 -fno-omit-frame-pointer -gline-tables-only -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=address -fsanitize-address-use-after-scope -fsanitize=fuzzer-no-link /src/pjsip/pjsip/lib/libpjsua-x86_64-unknown-linux-gnu.a /src/pjsip/pjsip/lib/libpjsip-ua-x86_64-unknown-linux-gnu.a /src/pjsip/pjsip/lib/libpjsip-simple-x86_64-unknown-linux-gnu.a /src/pjsip/pjsip/lib/libpjsip-x86_64-unknown-linux-gnu.a /src/pjsip/pjmedia/lib/libpjmedia-codec-x86_64-unknown-linux-gnu.a /src/pjsip/pjmedia/lib/libpjmedia-x86_64-unknown-linux-gnu.a /src/pjsip/pjmedia/lib/libpjmedia-videodev-x86_64-unknown-linux-gnu.a /src/pjsip/pjmedia/lib/libpjmedia-audiodev-x86_64-unknown-linux-gnu.a /src/pjsip/pjmedia/lib/libpjmedia-x86_64-unknown-linux-gnu.a /src/pjsip/pjnath/lib/libpjnath-x86_64-unknown-linux-gnu.a /src/pjsip/pjlib-util/lib/libpjlib-util-x86_64-unknown-linux-gnu.a /src/pjsip/pjlib/lib/libpj-x86_64-unknown-linux-gnu.a  -lm -lrt -lpthread -o $outexe
cp $outexe /out/
done


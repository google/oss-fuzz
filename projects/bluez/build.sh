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

./bootstrap
autoreconf -f
./configure
make

INCLUDES="-I. -I./src -I./lib -I./gobex -I/usr/local/include/glib-2.0/ -I/src/glib/_build/glib/"
STATIC_LIBS="./src/.libs/libshared-glib.a ./lib/.libs/libbluetooth-internal.a  -l:libical.a -l:libicalss.a -l:libicalvcal.a -l:libdbus-1.a /src/glib/_build/glib/libglib-2.0.a"

$CC $CFLAGS $LIB_FUZZING_ENGINE $INCLUDES \
 $SRC/fuzz_xml.c ./src/bluetoothd-sdp-xml.o -o $OUT/fuzz_xml \
 $STATIC_LIBS -ldl -lpthread

$CC $CFLAGS $LIB_FUZZING_ENGINE $INCLUDES \
 $SRC/fuzz_sdp.c -o $OUT/fuzz_sdp \
 $STATIC_LIBS -ldl -lpthread

$CC $CFLAGS $LIB_FUZZING_ENGINE $INCLUDES \
 $SRC/fuzz_textfile.c -o $OUT/fuzz_textfile \
 $STATIC_LIBS -ldl -lpthread src/textfile.o

$CC $CFLAGS $LIB_FUZZING_ENGINE $INCLUDES \
 $SRC/fuzz_gobex.c ./gobex/gobex*.o -o $OUT/fuzz_gobex \
 $STATIC_LIBS -ldl -lpthread

$CC $CFLAGS $LIB_FUZZING_ENGINE $INCLUDES \
 $SRC/fuzz_hci.c ./gobex/gobex*.o -o $OUT/fuzz_hci \
 $STATIC_LIBS -ldl -lpthread

set +e
projectName=bluez
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
/usr/local/bin/clang-15 -isystem /usr/local/lib/clang/15.0.0/include -isystem /usr/local/include -isystem /usr/include/x86_64-linux-gnu -isystem /usr/include -O1 -fno-omit-frame-pointer -gline-tables-only -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=address -fsanitize-address-use-after-scope -fsanitize=fuzzer-no-link -fsanitize=fuzzer -I/work/include -fuse-ld=lld $outfile /src/bluez/src/.libs/libshared-glib.a /src/bluez/lib/.libs/libbluetooth-internal.a -l:libical.a -l:libicalss.a -l:libicalvcal.a -l:libdbus-1.a /src/glib/_build/glib/libglib-2.0.a -ldl -lpthread -o $outexe
cp $outexe /out/
done


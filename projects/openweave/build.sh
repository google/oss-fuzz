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

git apply  --ignore-space-change --ignore-whitespace $SRC/patch.diff

function copy_lib
    {
    local fuzzer_path=$1
    local lib=$2
    cp $(ldd ${fuzzer_path} | grep "${lib}" | awk '{ print $3 }') ${OUT}/lib
    }

mkdir -p $OUT/lib

if [ "$SANITIZER" = "coverage" ]
then
    # so that we do not get openssl
    export CXXFLAGS="$CXXFLAGS -fsanitize=fuzzer-no-link,address"
    export CFLAGS="$CFLAGS -fsanitize=fuzzer-no-link,address"
fi

# build project
./bootstrap
# java fails with Source option 6 is no longer supported. Use 7 or later.
./configure --disable-java --enable-fuzzing --disable-shared

# patch bluez
sed -i 's/sys\/socket.h>/sys\/socket.h>\n#include <linux\/sockios.h>/g' ./third_party/bluez/repo/tools/l2test.c
sed -i 's/sys\/stat.h>/sys\/stat.h>\n#include <linux\/sockios.h>/g' ./third_party/bluez/repo/tools/rctest.c

# OpenSSL now declares RAND_bytes so we must patch
find ./src/test-apps/fuzz/ -name "FuzzP*.cpp" -exec sed -i 's/RAND_bytes/RAND_bytes2/g' {} \;

make -j$(nproc)

find src/test-apps/fuzz/ -type f -executable -name "Fuzz*" | while read i; do
    patchelf --set-rpath '$ORIGIN/lib' ${i}
    copy_lib ${i} libglib
    copy_lib ${i} libdbus
    cp ${i} $OUT/
done

# build corpus
ls $SRC/openweave-core/src/test-apps/fuzz/corpus/ | while read f; do
    zip -j $OUT/${f}_seed_corpus.zip $SRC/openweave-core/src/test-apps/fuzz/corpus/${f}/*;
done

cd $OUT/
ls *_seed_corpus.zip | grep PASE | while read c; do
    cp $c Fuzz$c;
done


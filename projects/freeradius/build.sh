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

function copy_lib
    {
    local fuzzer_path=$1
    local lib=$2
    cp $(ldd ${fuzzer_path} | grep "${lib}" | awk '{ print $3 }') ${OUT}/lib
    }

mkdir -p $OUT/lib

# git apply --ignore-whitespace $SRC/patch.diff
# build project
./configure --enable-fuzzer --enable-coverage --enable-address-sanitizer
# make tries to compile regular programs as fuzz targets
# so -i flag ignores these errors
make -i -j$(nproc)
make -i install
# use shared libraries
ldconfig
ls ./build/bin/local/fuzzer_* | while read i; do
    patchelf --set-rpath '$ORIGIN/lib' ${i}
    copy_lib ${i} libfreeradius
    copy_lib ${i} talloc
    copy_lib ${i} kqueue
    copy_lib ${i} libunwind
    cp ${i} $OUT/
done
cp -r /usr/local/share/freeradius/dictionary $OUT/dict
# export FR_DICTIONARY_DIR=/out/dictionary/
# export FR_LIBRARY_PATH=/out/lib/

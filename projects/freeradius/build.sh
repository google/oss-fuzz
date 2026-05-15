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

# Build json-c statically with the current sanitizer CFLAGS so it is
# instrumented and gets linked into fuzzer_json with no runtime shared
# library dependency on libjson-c.so.
mkdir -p $SRC/json-c-build
pushd $SRC/json-c-build
cmake $SRC/json-c \
    -DCMAKE_INSTALL_PREFIX=${JSONC_PREFIX} \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_SHARED_LIBS=OFF \
    -DBUILD_STATIC_LIBS=ON \
    -DDISABLE_WERROR=ON \
    -DBUILD_TESTING=OFF \
    -DCMAKE_C_COMPILER="$CC" \
    -DCMAKE_C_FLAGS="$CFLAGS -fPIC"
make -j$(nproc)
make install
popd

# git apply --ignore-whitespace $SRC/patch.diff
# fuzzer_json.mk doesn't pull in the json-c include path; inject it and
# force static linking against our instrumented libjson-c.a.
sed -i \
    -e "s|^SRC_CFLAGS\s*+= -I\$(top_builddir)/src/lib/json/|SRC_CFLAGS += -I\$(top_builddir)/src/lib/json/ -I${JSONC_PREFIX}/include|" \
    -e "s|-ljson-c|${JSONC_PREFIX}/lib/libjson-c.a|" \
    src/bin/fuzzer_json.mk
cat src/bin/fuzzer_json.mk

# build project — point FreeRADIUS' json-c probe at our static build
./configure --enable-fuzzer --enable-coverage --enable-address-sanitizer \
    --with-jsonc-include-dir=${JSONC_PREFIX}/include \
    --with-jsonc-lib-dir=${JSONC_PREFIX}/lib
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

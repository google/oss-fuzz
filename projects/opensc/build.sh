#!/bin/bash -eu
# Copyright 2019 Google Inc.
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

# Build OpenPACE
git clone https://github.com/frankmorgner/openpace.git
pushd openpace
autoreconf --verbose --install
./configure --enable-static --disable-shared --prefix=/usr
make
make install
popd

# enable internal and old drivers
sed -i '/^#ifdef OPENSC_CONFIG_STRING/i #define OPENSC_CONFIG_STRING "app default { card_drivers = old, internal; }"' src/libopensc/ctx.c

./bootstrap
# FIXME FUZZING_LIBS="$LIB_FUZZING_ENGINE" fails with some missing C++ library, I don't know how to fix this
./configure --disable-optimization --enable-static --disable-shared --disable-pcsc --enable-ctapi --enable-openpace --enable-fuzzing FUZZING_LIBS="$LIB_FUZZING_ENGINE"
make -j4

fuzzerFiles=$(find $SRC/opensc/src/tests/fuzzing/ -name "fuzz_*.c")

for F in $fuzzerFiles; do
    fuzzerName=$(basename $F .c)
    cp "$SRC/opensc/src/tests/fuzzing/$fuzzerName" $OUT
    if [ -d "$SRC/opensc/src/tests/fuzzing/corpus/${fuzzerName}" ]; then
        zip -j $OUT/${fuzzerName}_seed_corpus.zip $SRC/opensc/src/tests/fuzzing/corpus/${fuzzerName}/*
    fi
done

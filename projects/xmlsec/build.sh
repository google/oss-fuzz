#!/bin/bash -eu
#
# Copyright 2016 Google Inc.
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

# Build dependencies.
export XMLSEC_DEPS_PATH=$SRC/xmlsec_deps
mkdir -p $XMLSEC_DEPS_PATH

cd $SRC/libxml2
./autogen.sh \
    --without-legacy \
    --without-push \
    --without-python \
    --without-zlib \
    --without-lzma \
    --enable-static \
    --prefix="$XMLSEC_DEPS_PATH"
make -j$(nproc) all
make install

cd $SRC/libxslt
cd ../libxslt
./autogen.sh \
    --with-libxml-src=../libxml2 \
    --without-python \
    --without-debug \
    --without-debugger \
    --without-profiler \
    --enable-static \
    --prefix="$XMLSEC_DEPS_PATH"

make -j$(nproc)
make install

cd $SRC/xmlsec
autoreconf -vfi
./configure \
  --enable-static-linking \
  --enable-development \
  --with-libxml="$XMLSEC_DEPS_PATH" \
  --with-libxslt="$XMLSEC_DEPS_PATH"
make -j$(nproc) clean
make -j$(nproc) all

for file in $SRC/xmlsec/tests/oss-fuzz/*_target.c; do
    b=$(basename $file _target.c)
    echo -e "#include <stdint.h>\n$(cat $file)" > $file
    $CC $CFLAGS -c $file -I${XMLSEC_DEPS_PATH=}/include/libxml2 -I${XMLSEC_DEPS_PATH=}/include/ -I ./include/ \
    -o $OUT/${b}_target.o
    $CXX $CXXFLAGS $OUT/${b}_target.o ./src/.libs/libxmlsec1.a \
    ./src/openssl/.libs/libxmlsec1-openssl.a $LIB_FUZZING_ENGINE \
    "$XMLSEC_DEPS_PATH"/lib/libxslt.a "$XMLSEC_DEPS_PATH"/lib/libxml2.a \
    -lz -llzma -o $OUT/${b}_fuzzer
done
cp $SRC/xmlsec/tests/oss-fuzz/config/*.options $OUT/
wget -O $OUT/xml.dict https://raw.githubusercontent.com/mirrorer/afl/master/dictionaries/xml.dict

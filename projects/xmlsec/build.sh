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
sed -i 's/-pedantic-errors//g' configure.ac
sed -i 's/-pedantic//g' configure.ac
autoreconf -vfi

# Add non-standard search path
export CFLAGS="$CFLAGS -I$XMLSEC_DEPS_PATH/include"
export CXXFLAGS="$CXXFLAGS -I$XMLSEC_DEPS_PATH/include"

./configure \
  --enable-static-linking \
  --enable-development \
  --with-libxml="$XMLSEC_DEPS_PATH" \
  --with-libxslt="$XMLSEC_DEPS_PATH"
make -j$(nproc) clean
make -j$(nproc) all V=1

for file in $SRC/xmlsec/apps/oss-fuzz/*_target.c; do
    b=$(basename $file _target.c)
    $CC $CFLAGS -c $file -I${XMLSEC_DEPS_PATH=}/include/libxml2 -I${XMLSEC_DEPS_PATH=}/include/ -I ./include/ \
    -o $OUT/${b}_target.o
    $CXX $CXXFLAGS $OUT/${b}_target.o \
    -Wl,--start-group ./src/.libs/libxmlsec1.a \
    ./src/openssl/.libs/libxmlsec1-openssl.a -Wl,--end-group \
    $LIB_FUZZING_ENGINE \
    "$XMLSEC_DEPS_PATH"/lib/libxslt.a "$XMLSEC_DEPS_PATH"/lib/libxml2.a \
    -lz -llzma -lcrypto -lssl -o $OUT/${b}_fuzzer
done
cp $SRC/xmlsec/apps/oss-fuzz/config/*.options $OUT/
wget -O $OUT/xml.dict https://raw.githubusercontent.com/mirrorer/afl/master/dictionaries/xml.dict

# Seed corpus for the DSig verification fuzzer
zip -j $OUT/xmlsec_dsig_verify_fuzzer_seed_corpus.zip \
    $SRC/xmlsec/tests/phaos-xmldsig-three/signature*.xml \
    $SRC/xmlsec/tests/merlin-exc-c14n-one/*.xml \
    $SRC/xmlsec/tests/merlin-xmldsig-twenty-three/signature*.xml \
    2>/dev/null || true

# Seed corpus for the KeyInfo fuzzer: test files whose <KeyInfo> covers KeyName,
# the X509Data variants, RetrievalMethod and EncryptedKey
zip -j $OUT/xmlsec_keyinfo_fuzzer_seed_corpus.zip \
    $SRC/xmlsec/tests/merlin-xmldsig-twenty-three/signature-keyname.* \
    $SRC/xmlsec/tests/merlin-xmldsig-twenty-three/signature-x509-*.* \
    $SRC/xmlsec/tests/merlin-xmldsig-twenty-three/signature-retrievalmethod-*.* \
    $SRC/xmlsec/tests/phaos-xmldsig-three/signature-rsa-manifest-x509-data-*.xml \
    $SRC/xmlsec/tests/phaos-xmldsig-three/signature-rsa-*x509-data-crl.xml \
    $SRC/xmlsec/tests/merlin-xmlenc-five/encrypt-*.xml \
    2>/dev/null || true

# Seed corpus for the XML Encryption fuzzer: encrypted documents covering the
# cipher, key wrap, RSA key transport and key agreement variants. Each name is
# prefixed with its test directory because zip -j refuses a repeated name and
# more than one of these directories holds a keys.xml.
enc_corpus="$WORK/enc_corpus"
rm -rf "$enc_corpus"
mkdir -p "$enc_corpus"
for d in merlin-xmlenc-five 01-phaos-xmlenc-3 aleksey-xmlenc-01; do
    for f in $SRC/xmlsec/tests/$d/*.xml; do
        [ -f "$f" ] && cp "$f" "$enc_corpus/$d-$(basename $f)"
    done
done
zip -j $OUT/xmlsec_enc_fuzzer_seed_corpus.zip "$enc_corpus"/* 2>/dev/null || true

# Seed corpus for the key loader fuzzer with specific format
keyload_corpus="$WORK/keyload_corpus"
rm -rf "$keyload_corpus"
mkdir -p "$keyload_corpus"
prefix_seed() {
    # $1 = format byte, $2 = source file
    printf "$1" > "$keyload_corpus/$(basename $2).seed"
    cat "$2" >> "$keyload_corpus/$(basename $2).seed"
}
for f in $SRC/xmlsec/tests/keys/*.pem $SRC/xmlsec/tests/keys/*/*.pem; do
    [ -f "$f" ] && prefix_seed '\x01' "$f"
done
for f in $SRC/xmlsec/tests/keys/*.der $SRC/xmlsec/tests/keys/*/*.der; do
    [ -f "$f" ] && prefix_seed '\x02' "$f"
done
for f in $SRC/xmlsec/tests/keys/*.p12 $SRC/xmlsec/tests/keys/*/*.p12; do
    [ -f "$f" ] && prefix_seed '\x05' "$f"
done
zip -j $OUT/xmlsec_keyload_fuzzer_seed_corpus.zip "$keyload_corpus"/* 2>/dev/null || true

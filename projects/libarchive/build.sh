#!/bin/bash -eu
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

# For fuzz-introspector. This is to exclude all libxml2 code from the
# fuzz-introspector reports.
export FUZZ_INTROSPECTOR_CONFIG=$SRC/fuzz_introspector_exclusion.config
cat > $FUZZ_INTROSPECTOR_CONFIG <<EOF
FILES_TO_AVOID
libxml2
EOF

DEPS=/deps

cd $SRC/libarchive

mkdir build2
cd build2
OPENSSL_CMAKE_ARGS=()
CRYPTO_LINK_FLAGS=(-Wl,-Bdynamic -lcrypto)
if [ "$SANITIZER" = "memory" ] && [ "$ARCHITECTURE" = "x86_64" ]; then
  OPENSSL_PREFIX="$WORK/openssl-msan"
  OPENSSL_BUILD="$WORK/openssl-build"
  rm -rf "$OPENSSL_BUILD" "$OPENSSL_PREFIX"
  mkdir -p "$OPENSSL_BUILD"
  (
    cd "$OPENSSL_BUILD"
    CC="$CC" CFLAGS="$CFLAGS -fPIC" "$SRC/openssl/Configure" linux-x86_64 \
      --prefix="$OPENSSL_PREFIX" --libdir=lib no-asm no-shared no-tests
    make -j"$(nproc)" build_libs
    make install_dev
  )
  OPENSSL_CMAKE_ARGS=(-DOPENSSL_ROOT_DIR="$OPENSSL_PREFIX" -DOPENSSL_USE_STATIC_LIBS=ON)
  CRYPTO_LINK_FLAGS=("$OPENSSL_PREFIX/lib/libcrypto.a" -Wl,-Bdynamic)
fi
cmake -DDONT_FAIL_ON_CRC_ERROR=ON -DENABLE_WERROR=OFF "${OPENSSL_CMAKE_ARGS[@]}" ../
make -j$(nproc)

# build seed
cp $SRC/libarchive/contrib/oss-fuzz/corpus.zip\
        $OUT/libarchive_fuzzer_seed_corpus.zip

# build fuzzer(s)
$CXX $CXXFLAGS -I../libarchive \
    $SRC/libarchive_fuzzer.cc -o $OUT/libarchive_fuzzer \
    $LIB_FUZZING_ENGINE ./libarchive/libarchive.a \
    -Wl,-Bstatic -llzo2 "${CRYPTO_LINK_FLAGS[@]}" -lacl -llzma -llz4 -lbz2 -lz ${DEPS}/libxml2.a

# add the uuencoded test files
cd $SRC
mkdir ./uudecoded
find $SRC/libarchive/ -type f -name "test_extract.*.uu" -print0 | xargs -0 -I % cp -f % ./uudecoded/
cd ./uudecoded
find ./ -name "*.uu" -exec uudecode {} \;
cd ../
rm -f ./uudecoded/*.uu
zip -jr $OUT/libarchive_fuzzer_seed_corpus.zip ./uudecoded/*

# add weird archives
git clone --depth=1 https://github.com/corkami/pocs
find ./pocs/ -type f -print0 | xargs -0 -I % zip -jr $OUT/libarchive_fuzzer_seed_corpus.zip %

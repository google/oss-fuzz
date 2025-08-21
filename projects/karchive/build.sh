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

# build zstd
cd $SRC/zstd
cmake -S build/cmake -DBUILD_SHARED_LIBS=OFF
make install -j$(nproc)

# Build zlib
cd $SRC/zlib
./configure --static
make install -j$(nproc)

# Build bzip2
# Inspired from ../bzip2/build
cd $SRC
tar xzf bzip2-*.tar.gz && rm -f bzip2-*.tar.gz
cd bzip2-*
SRCL=(blocksort.o huffman.o crctable.o randtable.o compress.o decompress.o bzlib.o)

for source in ${SRCL[@]}; do
    name=$(basename $source .o)
    $CC $CFLAGS -c ${name}.c
done
rm -f libbz2.a
ar cq libbz2.a ${SRCL[@]}
cp -f bzlib.h /usr/local/include
cp -f libbz2.a /usr/local/lib

# Build xz
export ORIG_CFLAGS="${CFLAGS}"
export ORIG_CXXFLAGS="${CXXFLAGS}"
unset CFLAGS
unset CXXFLAGS
cd $SRC/xz
./autogen.sh --no-po4a --no-doxygen
./configure --enable-static --disable-debug --disable-shared --disable-xz --disable-xzdec --disable-lzmainfo
make install -j$(nproc)
export CFLAGS="${ORIG_CFLAGS}"
export CXXFLAGS="${ORIG_CXXFLAGS}"

# Build openssl
cd $SRC/openssl
CONFIG_FLAGS="no-shared no-tests"
if [[ $CFLAGS = *sanitize=memory* ]]
then
    # Disable assembly for proper instrumentation
    CONFIG_FLAGS+=" no-asm"
fi
./config $CONFIG_FLAGS
make -j$(nproc)
make install_sw

# Build extra-cmake-modules
cd $SRC/extra-cmake-modules
cmake .
make install -j$(nproc)

# Build qtbase
cd $SRC/qtbase
./configure -no-glib -qt-libpng -qt-pcre -opensource -confirm-license -static -no-opengl -no-icu -platform linux-clang-libc++ -debug -prefix /usr -no-feature-gui -no-feature-sql -no-feature-network  -no-feature-xml -no-feature-dbus -no-feature-printsupport
cmake --build . --parallel $(nproc)
cmake --install .

# Build karchive
cd $SRC/karchive
rm -rf poqm
cmake . -DBUILD_SHARED_LIBS=OFF -DBUILD_TESTING=OFF
make install -j$(nproc)

# Build karchive_fuzzer
HANDLER_TYPES="K7Zip 7z karchive_fuzzer
        KAr ar karchive_fuzzer
        KTar tar karchive_fuzzer
        KZip zip karchive_fuzzer
        GZip tar_gz kcompressiondevice_fuzzer
        BZip2 tar_bz2 kcompressiondevice_fuzzer
        Xz tar_xz kcompressiondevice_fuzzer
        Zstd tar_zst kcompressiondevice_fuzzer
        Lz tar_lz kcompressiondevice_fuzzer"

echo "$HANDLER_TYPES" | while read class format source_file; do
(
  fuzz_target_name=k${format}_fuzzer
  fuzz_target_flags="-DHANDLER=$class"

  if [[ "$class" == "K7Zip" ]]; then # KZip in future?
    fuzz_target_flags+=" -DUSE_PASSWORD"
  fi

  $CXX $CXXFLAGS -fPIC $fuzz_target_flags -std=c++17 $SRC/$source_file.cc -o $OUT/$fuzz_target_name \
    -I /usr/include/QtCore/ -I /usr/local/include/KF6/KArchive -lQt6Core -lm -lQt6BundledPcre2 \
    -ldl -lpthread $LIB_FUZZING_ENGINE /usr/local/lib/libz.a -lKF6Archive /usr/local/lib/libbz2.a \
    -llzma /usr/local/lib/libzstd.a /usr/local/lib64/libcrypto.a

  extension="${format/_/.}" # Replace _ with .
  files=$(find . -name "*.${extension}")
  if [ -n "$files" ]; then
    echo "$files" | zip -q $OUT/${fuzz_target_name}_seed_corpus.zip -@
  else
    echo "no files found with extension $extension for $fuzz_target_name seed corpus"
  fi

  if [ -f "$SRC/$fuzz_target_name.dict" ]; then
    cp "$SRC/$fuzz_target_name.dict" $OUT/
  fi
)
done

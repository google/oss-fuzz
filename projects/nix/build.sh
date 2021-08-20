#!/usr/bin/env bash
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

cd $SRC/nix

./bootstrap.sh

# `libcurl`'s `./configure` does not detect the entire dependency chain when compiling statically;
# See: https://github.com/curl/curl/discussions/6324 .
curl_extra_libs='-lunistring -llzma -licuuc -licudata'
libcurl_libs="$(pkg-config --static --libs libcurl) $curl_extra_libs"

# `libarchive` is missing dependency flags.
archive_extra_libs='-llzma -licuuc -licudata'
libarchive_libs="$(pkg-config --static --libs libarchive) $archive_extra_libs"

libutil_FLAGS="-fsanitize=fuzzer-no-link"
libstore_FLAGS="-fsanitize=fuzzer-no-link"
for S in $SANITIZER; do
  libutil_FLAGS+="-fsanitize=S"
  libstore_FLAGS+="-fsanitize=S"
done

LIBARCHIVE_LIBS=$libarchive_libs \
LIBCURL_LIBS=$libcurl_libs \
libutil_CXXFLAGS=$libutil_FLAGS \
libutil_LDFLAGS=$libutil_FLAGS \
libstore_CXXFLAGS=$libstore_FLAGS \
libstore_LDFLAGS=$libstore_FLAGS \
./configure \
  --enable-shared=no \
  --enable-gc=no \
  --prefix=$OUT

make clean

OPTIMIZE=0 ENABLE_S3=0 make -j$(nproc) fuzz/parse_store_path
mv fuzz/parse_store_path $OUT/

cd -

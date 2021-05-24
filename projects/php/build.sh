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

# build oniguruma and link statically
pushd oniguruma
autoreconf -vfi
./configure
make -j$(nproc)
popd
export ONIG_CFLAGS="-I$PWD/oniguruma/src"
export ONIG_LIBS="-L$PWD/oniguruma/src/.libs -l:libonig.a"

# PHP's zend_function union is incompatible with the object-size sanitizer
export CFLAGS="$CFLAGS -fno-sanitize=object-size"
export CXXFLAGS="$CXXFLAGS -fno-sanitize=object-size"

# Make sure the right assembly files are picked
BUILD_FLAG=""
if [ "$ARCHITECTURE" = "i386" ]; then
    BUILD_FLAG="--build=i686-pc-linux-gnu"
fi

# build project
./buildconf
./configure $BUILD_FLAG \
    --disable-all \
    --enable-debug-assertions \
    --enable-option-checking=fatal \
    --enable-fuzzer \
    --enable-exif \
    --enable-mbstring \
    --without-pcre-jit \
    --disable-phpdbg \
    --disable-cgi \
    --with-pic
make -j$(nproc)

# Generate corpuses and dictionaries.
sapi/cli/php sapi/fuzzer/generate_all.php

# Copy dictionaries to expected locations.
cp sapi/fuzzer/dict/unserialize $OUT/php-fuzz-unserialize.dict
cp sapi/fuzzer/dict/parser $OUT/php-fuzz-parser.dict
cp sapi/fuzzer/json.dict $OUT/php-fuzz-json.dict

FUZZERS="php-fuzz-json
php-fuzz-exif
php-fuzz-mbstring
php-fuzz-unserialize
php-fuzz-unserializehash
php-fuzz-parser
php-fuzz-execute"
for fuzzerName in $FUZZERS; do
	cp sapi/fuzzer/$fuzzerName $OUT/
done
# copy corpora from source
for fuzzerName in `ls sapi/fuzzer/corpus`; do
	zip -j $OUT/php-fuzz-${fuzzerName}_seed_corpus.zip sapi/fuzzer/corpus/${fuzzerName}/*
done


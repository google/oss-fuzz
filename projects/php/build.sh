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

# PHP's zend_function union is incompatible with the object-size sanitizer
export CFLAGS="$CFLAGS -fno-sanitize=object-size"
export CXXFLAGS="$CXXFLAGS -fno-sanitize=object-size"

# Disable JIT profitability checks.
export CFLAGS="$CFLAGS -DPROFITABILITY_CHECKS=0"

# Make sure the right assembly files are picked
BUILD_FLAG=""
if [ "$ARCHITECTURE" = "i386" ]; then
    BUILD_FLAG="--build=i686-pc-linux-gnu"
fi

# Build an instrumented libonig for mbregex.
pushd $SRC/oniguruma
autoreconf -vfi
./configure $BUILD_FLAG --disable-shared --enable-static
make -j$(nproc)
popd
export ONIG_CFLAGS="-I$SRC/oniguruma/src"
export ONIG_LIBS="-L$SRC/oniguruma/src/.libs -l:libonig.a"

# libonig is not clean under ubsan, see sapi/fuzzer/README.md.
MBREGEX_FLAG=""
if [ "$SANITIZER" = "undefined" ]; then
    MBREGEX_FLAG="--disable-mbregex"
fi

# build project
./buildconf
./configure $BUILD_FLAG \
    --disable-all \
    --enable-debug-assertions \
    --enable-option-checking=fatal \
    --enable-fuzzer \
    --enable-exif \
    --enable-mbstring $MBREGEX_FLAG \
    --without-pcre-jit \
    --disable-phpdbg \
    --disable-cgi \
    --enable-pic
make -j$(nproc)

# Generate corpuses and dictionaries.
sapi/cli/php sapi/fuzzer/generate_all.php

# Copy dictionaries to expected locations.
cp sapi/fuzzer/dict/unserialize $OUT/php-fuzz-unserialize.dict
cp sapi/fuzzer/dict/parser $OUT/php-fuzz-parser.dict
cp sapi/fuzzer/json.dict $OUT/php-fuzz-json.dict
cp sapi/fuzzer/dict/mbstring $OUT/php-fuzz-mbstring.dict
if [ -f sapi/fuzzer/dict/execute ]; then
    for fuzzerName in php-fuzz-execute php-fuzz-function-jit php-fuzz-tracing-jit; do
        cp sapi/fuzzer/dict/execute $OUT/$fuzzerName.dict
    done
fi

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

# Not built in every configuration or with every php-src version.
for fuzzerName in php-fuzz-mbregex php-fuzz-uri; do
	if [ -f sapi/fuzzer/$fuzzerName ]; then
		cp sapi/fuzzer/$fuzzerName $OUT/
	fi
done

# The JIT fuzzer is fundamentally incompatible with memory sanitizer,
# as that would require the JIT to emit msan instrumentation itself.
# In practice it is currently also incompatible with ubsan.
if [ "$SANITIZER" != "memory" ] && [ "$SANITIZER" != "undefined" ]; then
    cp sapi/fuzzer/php-fuzz-function-jit $OUT/
    cp sapi/fuzzer/php-fuzz-tracing-jit $OUT/
fi

# copy corpora from source
for fuzzerName in `ls sapi/fuzzer/corpus`; do
	zip -j $OUT/php-fuzz-${fuzzerName}_seed_corpus.zip sapi/fuzzer/corpus/${fuzzerName}/*
done


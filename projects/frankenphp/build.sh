#!/bin/bash -eu
# Copyright 2026 Google LLC
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

# FrankenPHP embeds a ZTS build of PHP, linked statically so the fuzzers run without libphp.so.
pushd $SRC/php-src
./buildconf --force
./configure \
    --prefix=$SRC/php \
    --disable-all \
    --enable-embed=static \
    --enable-zts \
    --enable-session \
    --disable-zend-signals \
    --enable-zend-max-execution-timers \
    --enable-debug-assertions \
    --without-pcre-jit \
    --disable-phpdbg \
    --disable-cgi
make -j$(nproc)
make install
popd

PHP_CONFIG=$SRC/php/bin/php-config
export CGO_CFLAGS="$CFLAGS $($PHP_CONFIG --includes)"
export CGO_LDFLAGS="$CFLAGS -L$SRC/php/lib $($PHP_CONFIG --ldflags) -lphp $($PHP_CONFIG --libs)"
tags="gofuzz,nowatcher"

go get github.com/AdamKorcz/go-118-fuzz-build/testing

# compile_native_go_fuzzer hardcodes -tags gofuzz and omits cgo libraries at link time, so build the fuzzers here.
for fuzzer in FuzzSplitPos FuzzSanitizedPathJoin FuzzSplitRemoteAddr; do
    if [[ $SANITIZER == *coverage* ]]; then
        mkdir -p $OUT/rawfuzzers
        go test -tags "$tags" -c -run "$fuzzer" -o "$OUT/$fuzzer" -cover .
        cp cgi_test.go "$OUT/rawfuzzers/$fuzzer"
        echo "s=github.com/dunglas/frankenphp=$PWD=" > "$OUT/$fuzzer.gocovpath"
    else
        go-118-fuzz-build -tags "$tags" -o "$fuzzer.a" -func "$fuzzer" .
        $CXX $CXXFLAGS $LIB_FUZZING_ENGINE "$fuzzer.a" $CGO_LDFLAGS -o "$OUT/$fuzzer"
    fi
done

#!/bin/bash -eu
# Copyright 2024 Google LLC
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

# Build squid with fuzzing instrumentation.
#
# Targets:
#   fuzz_http1_request_parser  — Http1 request-line + header block parser
#   fuzz_http1_response_parser — Http1 response status-line + header block parser
#   fuzz_chunked_decoder       — Transfer-Encoding: chunked body decoder
#   fuzz_request_uri           — URI parsing via HttpRequest::fromUrlXXX

cd $SRC/squid

# --- Configure ---
# Disable features that require external daemons / network access.
./bootstrap.sh 2>&1 | tail -5

./configure \
    CC="$CC" \
    CXX="$CXX" \
    CFLAGS="$CFLAGS" \
    CXXFLAGS="$CXXFLAGS" \
    LDFLAGS="$LIB_FUZZING_ENGINE" \
    --prefix=/usr/local/squid \
    --disable-external-acl-helpers \
    --disable-auth \
    --disable-auth-basic \
    --disable-auth-digest \
    --disable-auth-negotiate \
    --disable-auth-ntlm \
    --disable-url-rewrite-helpers \
    --disable-log-daemon-helpers \
    --disable-ssl-crtd \
    --without-openssl \
    --without-gnutls \
    --without-libcap \
    --without-nettle \
    --without-libmaxminddb \
    --without-mit-krb5 \
    --without-heimdal-krb5 \
    --without-ntlm-auth-helper \
    --with-maxfd=1024 \
    2>&1 | tail -20

# Build only the core library components needed by the fuzzers
make -j$(nproc) \
    src/libsquid.la \
    src/http/libsquid-http.la \
    src/parser/libsquid-parser.la \
    src/sbuf/libsbuf.la \
    2>&1 | tail -30 || true

# --- Copy fuzz sources from project dir ---
cp $SRC/squid/tests/fuzz/*.cc src/tests/ 2>/dev/null || \
cp $SRC/oss-fuzz/projects/squid/fuzz_*.cc src/tests/

# --- Build each fuzzer ---
for target in fuzz_http1_request_parser fuzz_http1_response_parser fuzz_chunked_decoder; do
    $CXX $CXXFLAGS \
        -I$SRC/squid \
        -I$SRC/squid/include \
        -I$SRC/squid/src \
        -I$SRC/squid/lib \
        $SRC/oss-fuzz/projects/squid/${target}.cc \
        src/.libs/libsquid.a \
        src/http/.libs/libsquid-http.a \
        src/parser/.libs/libsquid-parser.a \
        src/sbuf/.libs/libsbuf.a \
        $LIB_FUZZING_ENGINE \
        -o $OUT/${target} 2>&1 | tail -5
done

# Copy seed corpora
cp $SRC/oss-fuzz/projects/squid/seeds/http_requests.zip \
    $OUT/fuzz_http1_request_parser_seed_corpus.zip 2>/dev/null || true
cp $SRC/oss-fuzz/projects/squid/seeds/http_responses.zip \
    $OUT/fuzz_http1_response_parser_seed_corpus.zip 2>/dev/null || true

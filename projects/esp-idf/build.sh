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

# ESP-IDF is primarily an embedded SDK targeting Xtensa/RISC-V SoCs and most
# components require the IDF build system together with the cross-compilation
# toolchain. For the initial OSS-Fuzz integration we fuzz components that are
# self-contained portable C and can be compiled natively with the fuzzer
# instrumentation.

HTTP_PARSER_DIR="$SRC/esp-idf/components/http_parser"

# Compile the http_parser source as a standalone object file using the
# OSS-Fuzz sanitizer/coverage flags.
$CC $CFLAGS -I"$HTTP_PARSER_DIR" \
    -c "$HTTP_PARSER_DIR/http_parser.c" \
    -o "$WORK/http_parser.o"

# fuzz_http_parser: feeds bytes to http_parser_execute() in request/response/both modes.
$CC $CFLAGS -I"$HTTP_PARSER_DIR" \
    -c "$SRC/fuzz_http_parser.c" \
    -o "$WORK/fuzz_http_parser.o"

$CXX $CXXFLAGS \
    "$WORK/fuzz_http_parser.o" \
    "$WORK/http_parser.o" \
    $LIB_FUZZING_ENGINE \
    -o "$OUT/fuzz_http_parser"

# fuzz_http_parser_url: exercises http_parser_parse_url() with and without connect=true.
$CC $CFLAGS -I"$HTTP_PARSER_DIR" \
    -c "$SRC/fuzz_http_parser_url.c" \
    -o "$WORK/fuzz_http_parser_url.o"

$CXX $CXXFLAGS \
    "$WORK/fuzz_http_parser_url.o" \
    "$WORK/http_parser.o" \
    $LIB_FUZZING_ENGINE \
    -o "$OUT/fuzz_http_parser_url"

# Dictionary of HTTP tokens to help the fuzzer reach the parser's interesting
# states (methods, versions, common headers, transfer-encoding values, etc.).
# NOTE: libFuzzer's dictionary format only supports \\, \" and \xNN escapes,
# so CRLF is encoded as \x0d\x0a.
cat > "$OUT/fuzz_http_parser.dict" <<'DICT'
"GET "
"PUT "
"POST "
"HEAD "
"DELETE "
"OPTIONS "
"TRACE "
"CONNECT "
"PATCH "
"PROPFIND "
"PROPPATCH "
"MKCOL "
"COPY "
"MOVE "
"LOCK "
"UNLOCK "
"REPORT "
"MKACTIVITY "
"CHECKOUT "
"MERGE "
"M-SEARCH "
"NOTIFY "
"SUBSCRIBE "
"UNSUBSCRIBE "
"PURGE "
"MKCALENDAR "
" HTTP/1.0\x0d\x0a"
" HTTP/1.1\x0d\x0a"
" HTTP/2.0\x0d\x0a"
"\x0d\x0a"
"\x0d\x0a\x0d\x0a"
"Host: "
"Content-Length: "
"Content-Type: "
"Transfer-Encoding: chunked\x0d\x0a"
"Connection: close\x0d\x0a"
"Connection: keep-alive\x0d\x0a"
"Connection: upgrade\x0d\x0a"
"Upgrade: websocket\x0d\x0a"
"Trailer: "
"Expect: 100-continue\x0d\x0a"
"chunked"
"identity"
"0\x0d\x0a\x0d\x0a"
"1\x0d\x0aA\x0d\x0a"
"HTTP/1.0 200 OK\x0d\x0a"
"HTTP/1.1 200 OK\x0d\x0a"
"HTTP/1.1 301 Moved Permanently\x0d\x0a"
"HTTP/1.1 304 Not Modified\x0d\x0a"
"HTTP/1.1 404 Not Found\x0d\x0a"
"HTTP/1.1 500 Internal Server Error\x0d\x0a"
DICT

cp "$OUT/fuzz_http_parser.dict" "$OUT/fuzz_http_parser_url.dict"

# Seed corpus for the message parser harness.
SEED_PARSER="$WORK/seeds_parser"
mkdir -p "$SEED_PARSER"

printf 'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n' \
    > "$SEED_PARSER/req_get"
printf 'POST /a HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\n\r\nabc' \
    > "$SEED_PARSER/req_post"
printf 'POST /a HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n' \
    > "$SEED_PARSER/req_chunked"
printf 'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok' \
    > "$SEED_PARSER/resp_ok"
printf 'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n' \
    > "$SEED_PARSER/resp_chunked"
printf 'GET /chat HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n' \
    > "$SEED_PARSER/req_upgrade"

(cd "$SEED_PARSER" && zip -q "$OUT/fuzz_http_parser_seed_corpus.zip" ./*)

# Seed corpus for the URL parser harness.
SEED_URL="$WORK/seeds_url"
mkdir -p "$SEED_URL"

printf 'http://example.com/'                      > "$SEED_URL/abs_simple"
printf 'https://user:pass@host:8080/p?q=1#f'      > "$SEED_URL/abs_full"
printf '/path/only?x=1'                           > "$SEED_URL/origin_form"
printf 'host:443'                                 > "$SEED_URL/connect_form"
printf 'coap://[::1]:5683/.well-known/core'       > "$SEED_URL/ipv6_coap"
printf '*'                                        > "$SEED_URL/asterisk"

(cd "$SEED_URL" && zip -q "$OUT/fuzz_http_parser_url_seed_corpus.zip" ./*)

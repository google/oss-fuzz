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

# Build libosip2 (static, instrumented) into a private prefix.
OSIP_PREFIX=$WORK/osip-install
mkdir -p $WORK/osip-build
cd $SRC/osip
autoreconf -fi
cd $WORK/osip-build
$SRC/osip/configure --prefix=$OSIP_PREFIX --enable-static --disable-shared
make -j$(nproc)
make install

export PKG_CONFIG_PATH=$OSIP_PREFIX/lib/pkgconfig

# Build only the SentryPeer sources the SIP parser fuzzer needs, without the
# Rust and OpenDHT (P2P) parts. The upstream warning flags include -Werror,
# so override AM_CFLAGS to keep newer compilers from failing the build.
cd $SRC/sentrypeer
./bootstrap.sh
LDFLAGS="${LDFLAGS:-} -L$OSIP_PREFIX/lib" CPPFLAGS="${CPPFLAGS:-} -I$OSIP_PREFIX/include" \
    ./configure --disable-rust --disable-opendht
SP_OBJS="src/sip_parser.o src/bad_actor.o src/utils.o src/conf.o src/database.o src/json_logger.o src/regex_match.o"
make -j$(nproc) AM_CFLAGS="-std=gnu18" $SP_OBJS

# Link the fuzz targets statically against SentryPeer and its dependencies.
for fuzzer in fuzz_sip_parser fuzz_http_input fuzz_json_bad_actor; do
    $CC $CFLAGS -I. -I$OSIP_PREFIX/include -c $SRC/$fuzzer.c -o $WORK/$fuzzer.o
    $CXX $CXXFLAGS $LIB_FUZZING_ENGINE $WORK/$fuzzer.o $SP_OBJS \
        $OSIP_PREFIX/lib/libosipparser2.a $OSIP_PREFIX/lib/libosip2.a \
        $(pkg-config --libs sqlite3 uuid libcurl jansson libpcre2-8) \
        -lpthread -lm -Wl,-rpath,'$ORIGIN/lib' -o $OUT/$fuzzer
done

# The runtime image doesn't have the distro libraries, so ship the shared
# ones (except the base C/C++ runtime) next to the fuzzers.
mkdir -p $OUT/lib
ldd $OUT/fuzz_sip_parser $OUT/fuzz_http_input $OUT/fuzz_json_bad_actor | awk '/=> \// {print $3}' | grep -v "^$OUT/" | sort -u \
    | grep -v -E '/(libc|libm|libdl|librt|libpthread|libgcc_s|libstdc\+\+)\.so' \
    | xargs -r cp -L -t $OUT/lib

# Seed corpus
mkdir -p $WORK/corpus
printf 'INVITE sip:100@example.com SIP/2.0\r\nVia: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK1\r\nFrom: <sip:1000@example.com>;tag=1\r\nTo: <sip:100@example.com>\r\nCall-ID: abc@10.0.0.1\r\nCSeq: 1 INVITE\r\nContact: <sip:1000@10.0.0.1>\r\nUser-Agent: friendly-scanner\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n' > $WORK/corpus/invite
printf 'OPTIONS sip:100@example.com SIP/2.0\r\nVia: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK2\r\nFrom: <sip:1000@example.com>;tag=2\r\nTo: <sip:100@example.com>\r\nCall-ID: def@10.0.0.1\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n' > $WORK/corpus/options
# A SIP response has no method; this must not abort the parser.
printf 'SIP/2.0 100 x\r\n' > $WORK/corpus/response_minimal
printf 'SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK3\r\nFrom: <sip:1000@example.com>;tag=3\r\nTo: <sip:100@example.com>;tag=4\r\nCall-ID: ghi@10.0.0.1\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n' > $WORK/corpus/response_ok
printf 'SIP/2.0 401 Unauthorized\r\nVia: SIP/2.0/TCP 10.0.0.1:5060;branch=z9hG4bK4\r\nCall-ID: jkl@10.0.0.1\r\nCSeq: 2 REGISTER\r\n\r\n' > $WORK/corpus/response_unauthorized
printf 'REGISTER sip:example.com SIP/2.0\r\nVia: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK5;rport\r\nFrom: "bob" <sip:1000@example.com>;tag=5\r\nTo: <sip:1000@example.com>\r\nCall-ID: mno@10.0.0.1\r\nCSeq: 2 REGISTER\r\nContact: <sip:1000@10.0.0.1:5060;transport=udp>;expires=60\r\nAuthorization: Digest username="1000", realm="example.com", nonce="abc", uri="sip:example.com", response="0123456789abcdef0123456789abcdef", algorithm=MD5, qop=auth, cnonce="x", nc=00000001\r\nAllow: INVITE, ACK, BYE, CANCEL, OPTIONS\r\nContent-Length: 0\r\n\r\n' > $WORK/corpus/register_auth
printf 'INVITE sip:100@example.com SIP/2.0\r\nv: SIP/2.0/TCP 10.0.0.1:5060;branch=z9hG4bK6\r\nf: <sip:1000@example.com>;tag=6\r\nt: <sip:100@example.com>\r\ni: pqr@10.0.0.1\r\nCSeq: 1 INVITE\r\nRoute: <sip:proxy.example.com;lr>\r\nRecord-Route: <sip:proxy.example.com;lr>\r\nc: application/sdp\r\nl: 60\r\n\r\nv=0\r\no=- 1 1 IN IP4 10.0.0.1\r\ns=-\r\nc=IN IP4 10.0.0.1\r\nt=0 0\r\nm=audio 4000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n' > $WORK/corpus/invite_sdp
printf 'SIP/2.0 407 Proxy Authentication Required\r\nVia: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK7\r\nTo: <sip:100@example.com>;tag=7\r\nFrom: <sip:1000@example.com>;tag=8\r\nCall-ID: stu@10.0.0.1\r\nCSeq: 1 INVITE\r\nProxy-Authenticate: Digest realm="example.com", nonce="abc", opaque="def", algorithm=MD5, qop="auth,auth-int"\r\nContent-Length: 0\r\n\r\n' > $WORK/corpus/response_proxy_auth
printf 'MESSAGE sip:100@example.com SIP/2.0\r\nVia: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK8\r\nFrom: <sip:1000@example.com>;tag=9\r\nTo: <sip:100@example.com>\r\nCall-ID: vwx@10.0.0.1\r\nCSeq: 1 MESSAGE\r\nContent-Type: multipart/mixed;boundary=b\r\nContent-Length: 70\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nhello\r\n--b\r\nContent-Type: application/sdp\r\n\r\nv=0\r\n--b--\r\n' > $WORK/corpus/message_multipart
cp $SRC/sip.dict $OUT/fuzz_sip_parser.dict
zip -j $OUT/fuzz_sip_parser_seed_corpus.zip $WORK/corpus/*

mkdir -p $WORK/http_corpus
printf '/ip-addresses/192.168.0.1' > $WORK/http_corpus/ip
printf '/ip-addresses/2001:db8::1' > $WORK/http_corpus/ip6
printf '/numbers/+441234567890' > $WORK/http_corpus/number
printf '/numbers/441234567890' > $WORK/http_corpus/number2
zip -j $OUT/fuzz_http_input_seed_corpus.zip $WORK/http_corpus/*

mkdir -p $WORK/json_corpus
cat > $WORK/json_corpus/bad_actor.json <<'JSON'
{"app_name":"sentrypeer","app_version":"5.0.0","event_timestamp":"2026-01-01 00:00:00","event_uuid":"7d1ae4f6-2d2b-4b5c-9f4c-0c6f6a2f6c11","created_by_node_id":"1c1c8e2a-3a4b-4c5d-8e9f-0a1b2c3d4e5f","collected_method":"passive","transport_type":"UDP","source_ip":"192.0.2.1","destination_ip":"192.0.2.2","called_number":"100","sip_method":"INVITE","sip_user_agent":"friendly-scanner","sip_message":"INVITE sip:100@example.com SIP/2.0\r\n\r\n"}
JSON
zip -j $OUT/fuzz_json_bad_actor_seed_corpus.zip $WORK/json_corpus/*

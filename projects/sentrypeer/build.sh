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
    $CC $CFLAGS -I. -I$OSIP_PREFIX/include -c $SRC/sentrypeer/tests/fuzz/$fuzzer.c -o $WORK/$fuzzer.o
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

# Fuzzers, dictionary and seed corpora live upstream in tests/fuzz.
FUZZ_DIR=$SRC/sentrypeer/tests/fuzz
cp $FUZZ_DIR/sip.dict $OUT/fuzz_sip_parser.dict
zip -j -q $OUT/fuzz_sip_parser_seed_corpus.zip $FUZZ_DIR/corpus/sip_parser/*
zip -j -q $OUT/fuzz_http_input_seed_corpus.zip $FUZZ_DIR/corpus/http_input/*
zip -j -q $OUT/fuzz_json_bad_actor_seed_corpus.zip $FUZZ_DIR/corpus/json_bad_actor/*

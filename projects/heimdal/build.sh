#!/bin/bash -eu
#
# Copyright 2023 Google LLC
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

export ASAN_OPTIONS="detect_leaks=0"
autoreconf -fi
./configure --enable-shared=no --enable-static=yes --disable-otp
make V=1 -j$(nproc)

$CC $CFLAGS -Iinclude/ -c $SRC/fuzz_json.c -o fuzz_json.o
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE fuzz_json.o -o $OUT/fuzz_json \
    -pthread  ./lib/gssapi/.libs/libgssapi.a /src/heimdal/lib/ntlm/.libs/libheimntlm.a \
    -L/lib /src/heimdal/lib/krb5/.libs/libkrb5.a ./lib/krb5/.libs/libkrb5.a            \
    /src/heimdal/lib/hx509/.libs/libhx509.a /src/heimdal/lib/wind/.libs/libwind.a      \
    /src/heimdal/lib/sqlite/.libs/libheimsqlite.a /src/heimdal/lib/hcrypto/.libs/libhcrypto.a \
    ./lib/hcrypto/.libs/libhcrypto.a /src/heimdal/lib/asn1/.libs/libasn1.a \
    /src/heimdal/lib/base/.libs/libheimbase.a -lcrypto ./lib/asn1/.libs/libasn1.a \
    /src/heimdal/lib/com_err/.libs/libcom_err.a /src/heimdal/lib/roken/.libs/libroken.a \
    ./lib/vers/.libs/libvers.a ./lib/roken/.libs/libroken.a -lresolv -lpthread -pthread

cp $SRC/*.options $OUT/

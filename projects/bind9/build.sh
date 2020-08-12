#!/bin/sh -eu
# Copyright 2020 Google LLC
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

# build the project
autoreconf -fi
./configure --disable-shared --enable-static --enable-developer --without-cmocka --without-zlib --disable-linux-caps --prefix="$WORK" --enable-fuzzing=ossfuzz
make -j"$(nproc)" all
(cd fuzz && TESTS='' make -e -j"$(nproc)" check)

LIBISC_CFLAGS="-Ilib/isc/unix/include -Ilib/isc/pthreads/include -Ilib/isc/include"
LIBDNS_CFLAGS="-Ilib/dns/include"
LIBISC_LIBS="libltdl/.libs/libltdlc.a lib/isc/.libs/libisc.a -Wl,-Bstatic -lcrypto -luv -Wl,-Bdynamic"
LIBDNS_LIBS="lib/dns/.libs/libdns.a -Wl,-Bstatic -lcrypto -Wl,-Bdynamic"

for fuzzer in fuzz/*.c; do
    output=$(basename "${fuzzer%.c}")
    [ "$output" = "main" ] && continue
    # We need to try little bit harder to link everything statically
    ${CXX} ${CXXFLAGS} \
	   -o "${OUT}/${output}_fuzzer" \
	   "fuzz/${output}.o" \
	   -include config.h \
	   $LIBISC_CFLAGS $LIBDNS_CFLAGS \
	   $LIBDNS_LIBS $LIBISC_LIBS $LIB_FUZZING_ENGINE
    zip -j "${OUT}/${output}_seed_corpus.zip" "fuzz/${output}.in/"*
done

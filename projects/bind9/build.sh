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
./configure --disable-shared --enable-static --enable-developer --without-cmocka --without-zlib --prefix="$WORK" --enable-fuzzing=ossfuzz
(cd lib/isc && make -j"$(nproc)" all V=1)
(cd lib/dns && make -j"$(nproc)" all V=1)

LIBISC_CFLAGS="-Ilib/isc/unix/include -Ilib/isc/pthreads/include -Ilib/isc/include"
LIBDNS_CFLAGS="-Ilib/dns/include"
LIBISC_LIBS="lib/isc/.libs/libisc.a -Wl,-Bstatic -Wl,-u,isc__initialize,-u,isc__shutdown -lssl -lcrypto -luv -lnghttp2 -Wl,-Bdynamic"
LIBDNS_LIBS="lib/dns/.libs/libdns.a -Wl,-Bstatic -lcrypto -Wl,-Bdynamic"

# dns_name_fromwire needs old.c/old.h code to be linked in
sed -i 's/#include "old.h"/#include "old.c"/' fuzz/dns_name_fromwire.c

for fuzzer in fuzz/*.c; do
    output=$(basename "${fuzzer%.c}")
    [ "$output" = "main" ] && continue
    [ "$output" = "old" ] && continue
    # We need to try little bit harder to link everything statically
    (cd fuzz && make -j"$(nproc)" "${output}.o" V=1)
    ${CXX} ${CXXFLAGS} \
	   -o "${OUT}/${output}_fuzzer" \
	   "fuzz/${output}.o" \
	   -include config.h \
	   $LIBISC_CFLAGS $LIBDNS_CFLAGS \
	   $LIBDNS_LIBS $LIBISC_LIBS $LIB_FUZZING_ENGINE
    zip -j "${OUT}/${output}_seed_corpus.zip" "fuzz/${output}.in/"*
done

#!/bin/bash -eu
# Copyright 2020 Google Inc.
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

# This is only used for local testing
#cp /src/fuzz-imap-url.c src/lib-imap/
#cp /src/fuzz-imap-utf7.c src/lib-imap/
#cp /src/fuzz-http-url.c src/lib-http/
#####################################

./autogen.sh
./configure PANDOC=false

make

cd src/lib-imap

echo $CFLAGS


# fuzz-imap-utf7
clang $CFLAGS -DHAVE_CONFIG_H -I. -I../..  -I../../src/lib -I../../src/lib-test -I../../src/lib-charset -I../../src/lib-mail   -std=gnu99 -fstack-protector-strong -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2 -Wall -W -Wmissing-prototypes -Wmissing-declarations -Wpointer-arith -Wchar-subscripts -Wformat=2 -Wbad-function-cast -Wno-duplicate-decl-specifier -Wstrict-aliasing=2   -MT test-imap-utf7.o -MD -MP -c -o fuzz-imap-utf7.o fuzz-imap-utf7.c

clang $CFLAGS $LIB_FUZZING_ENGINE -std=gnu99  -fstack-protector-strong -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2 -Wall -W -Wmissing-prototypes -Wmissing-declarations -Wpointer-arith -Wchar-subscripts -Wformat=2 -Wbad-function-cast -Wno-duplicate-decl-specifier -Wstrict-aliasing=2 -Wl,--as-needed -o $OUT/fuzz-imap-utf7 fuzz-imap-utf7.o .libs/imap-utf7.o .libs/imap-quote.o ../lib-test/.libs/libtest.a ../lib/.libs/liblib.a 

# fuzz-imap-url
clang $CFLAGS -DHAVE_CONFIG_H -I. -I../..  -I../../src/lib -I../../src/lib-test -I../../src/lib-charset -I../../src/lib-mail   -std=gnu99 -fstack-protector-strong -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2 -Wall -W -Wmissing-prototypes -Wmissing-declarations -Wpointer-arith -Wchar-subscripts -Wformat=2 -Wbad-function-cast -Wno-duplicate-decl-specifier -Wstrict-aliasing=2   -MT fuzz-imap-url.o -MD -MP  -c -o fuzz-imap-url.o fuzz-imap-url.c

clang $CFLAGS $LIB_FUZZING_ENGINE -std=gnu99 -fstack-protector-strong -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2 -Wall -W -Wmissing-prototypes -Wmissing-declarations -Wpointer-arith -Wchar-subscripts -Wformat=2 -Wbad-function-cast -Wno-duplicate-decl-specifier -Wstrict-aliasing=2 -Wl,--as-needed -o $OUT/fuzz-imap-url fuzz-imap-url.o .libs/imap-url.o  ../lib-test/.libs/libtest.a ../lib/.libs/liblib.a 



cd ../lib-http
# fuzz-http-url
clang $CFLAGS -DHAVE_CONFIG_H -I. -I../..  -I../../src/lib -I../../src/lib-test -I../../src/lib-dns -I../../src/lib-ssl-iostream -I../../src/lib-master -DPKG_RUNDIR=\""/usr/local/var/run/dovecot"\"   -std=gnu99 -fstack-protector-strong -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2 -Wall -W -Wmissing-prototypes -Wmissing-declarations -Wpointer-arith -Wchar-subscripts -Wformat=2 -Wbad-function-cast -Wno-duplicate-decl-specifier -Wstrict-aliasing=2   -MT fuzz-http-url.o -MD -MP  -c -o fuzz-http-url.o fuzz-http-url.c

clang $CFLAGS $LIB_FUZZING_ENGINE -std=gnu99 -fstack-protector-strong -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2 -Wall -W -Wmissing-prototypes -Wmissing-declarations -Wpointer-arith -Wchar-subscripts -Wformat=2 -Wbad-function-cast -Wno-duplicate-decl-specifier -Wstrict-aliasing=2 -Wl,--as-needed -o $OUT/fuzz-http-url fuzz-http-url.o .libs/http-url.o .libs/http-header.o -Wl,--export-dynamic  ../lib-test/.libs/libtest.a ../lib/.libs/liblib.a

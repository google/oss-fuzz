#!/bin/bash -eu
# Copyright 2021 Google LLC
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

cd postfix
make makefiles CCARGS="${CFLAGS}"
make
BASE=$PWD

# Compile fuzzers
cd ${BASE}/src/global
$CC $CFLAGS -DHAS_DEV_URANDOM -DSNAPSHOT -UUSE_DYNAMIC_LIBS -DDEF_SHLIB_DIR=\"no\" \
               -UUSE_DYNAMIC_MAPS -I. -I../../include -DNO_EAI -DDEF_SMTPUTF8_ENABLE=\"no\" \
                -g -O -DLINUX4 -Wformat -Wno-comment -fno-common -c $SRC/fuzz_tok822.c
$CC $CFLAGS -DHAS_DEV_URANDOM -DSNAPSHOT -UUSE_DYNAMIC_LIBS -DDEF_SHLIB_DIR=\"no\" \
               -UUSE_DYNAMIC_MAPS -I. -I../../include -DNO_EAI -DDEF_SMTPUTF8_ENABLE=\"no\" \
                -g -O -DLINUX4 -Wformat -Wno-comment -fno-common -c $SRC/fuzz_mime.c

# Link fuzzers
cd ${BASE}
$CC $CFLAGS $LIB_FUZZING_ENGINE ./src/global/fuzz_tok822.o -o $OUT/fuzz_tok822 \
  ./lib/libglobal.a ./lib/libutil.a
$CC $CFLAGS $LIB_FUZZING_ENGINE ./src/global/fuzz_mime.o -o $OUT/fuzz_mime \
  ./lib/libglobal.a ./lib/libutil.a -ldb -lnsl

set +e
for outfile in $(find /src/*/fuzzdrivers -name "*.c"); do
outexe=${outfile%.*}
echo $outexe
/usr/local/bin/clang-15 -isystem /usr/local/lib/clang/15.0.0/include -isystem /usr/local/include -isystem /usr/include/x86_64-linux-gnu -isystem /usr/include -fsanitize=address -fsanitize=fuzzer -I/work/include -O1 -fno-omit-frame-pointer -gline-tables-only -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=address -fsanitize-address-use-after-scope -fsanitize=fuzzer-no-link -DHAS_DEV_URANDOM -DSNAPSHOT -UUSE_DYNAMIC_LIBS -DDEF_SHLIB_DIR='no' -UUSE_DYNAMIC_MAPS -I/src/postfix/postfix/src/global -I/src/postfix/postfix/include $outfile -o $outexe /src/postfix/postfix/lib/libglobal.a /src/postfix/postfix/lib/libutil.a /src/postfix/postfix/lib/libdns.a  /src/postfix/postfix/lib/libmaster.a /src/postfix/postfix/lib/libmilter.a /src/postfix/postfix/lib/libtls.a /src/postfix/postfix/lib/libxsasl.a -ldb -lnsl
cp $outexe /out/
done


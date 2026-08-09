#!/bin/bash -eu
# Copyright 2018 Google Inc.
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

# Dependencies are already built in the Docker image
cd /src/gnupg
./autogen.sh  
./configure --enable-maintainer-mode --disable-doc --disable-tests --disable-nls \
  --disable-sqlite --disable-gnutls --disable-ldap --disable-card-support \
  CFLAGS="$CFLAGS" CXXFLAGS="$CXXFLAGS"

# Generate built sources first (status-codes.h, audit-events.h, etc.)
make -j$(nproc) -C common audit-events.h status-codes.h
make -j$(nproc) -C regexp _unicode_mapping.c
# Build only needed components  
make -j$(nproc) -C common libcommon.a libcommonpth.a libgpgrl.a
make -j$(nproc) -C regexp libregexp.a
make -j$(nproc) -C kbx libkeybox.a
# Build g10 - just build the gpg program which compiles all needed objects
make -j$(nproc) -C g10 gpg
# Create a library archive from all the compiled objects, excluding gpg.o which has main()
mkdir -p g10/.libs
find g10 -name '*.o' -type f ! -name 'gpg.o' ! -name 't-*.o' | xargs ar cru g10/.libs/libgpg.a
ranlib g10/.libs/libgpg.a

# Build fuzzers
cd /src/gnupg

# Compile the fuzzer stubs that provide opt and glo_ctrl
$CC $CFLAGS -I. -Icommon -Ig10 -c /src/fuzzer_stubs.c -o fuzzer_stubs.o

for fuzzer in fuzz_decrypt fuzz_import fuzz_list fuzz_verify; do
  [ -f /src/${fuzzer}.c ] || continue
  $CC $CFLAGS -I. -Icommon -Ig10 -c /src/${fuzzer}.c -o ${fuzzer}.o
  $CXX $CXXFLAGS fuzzer_stubs.o ${fuzzer}.o \
    g10/.libs/libgpg.a \
    kbx/libkeybox.a \
    common/libcommonpth.a \
    regexp/libregexp.a \
    common/libgpgrl.a \
    $LIB_FUZZING_ENGINE \
    -lgcrypt -lgpg-error -lassuan -lksba -lnpth -lutil \
    -o $OUT/${fuzzer}
done

cp /src/*.options $OUT/ 2>/dev/null || true


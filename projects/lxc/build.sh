#!/bin/bash -e
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

# -fsanitize=... isn't compatible with -Wl,-no-undefined
# https://github.com/google/sanitizers/issues/380
sed -i 's/-Wl,-no-undefined *\\/\\/' src/lxc/Makefile.am

# AFL++ and hoggfuzz are both incompatible with lto=thin apparently
sed -i '/-flto=thin/d' configure.ac

# turn off the libutil dependency
sed -i 's/^AC_CHECK_LIB(util/#/' configure.ac

./autogen.sh
./configure \
    --disable-tools \
    --disable-commands \
    --disable-apparmor \
    --disable-openssl \
    --disable-selinux \
    --disable-seccomp \
    --disable-capabilities

make -j$(nproc)

$CC -c -o fuzz-lxc-config-read.o $CFLAGS -Isrc -Isrc/lxc $SRC/fuzz-lxc-config-read.c
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE fuzz-lxc-config-read.o src/lxc/.libs/liblxc.a -o $OUT/fuzz-lxc-config-read

zip -r $OUT/fuzz-lxc-config-read_seed_corpus.zip doc/examples

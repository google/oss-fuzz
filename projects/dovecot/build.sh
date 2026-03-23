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
cd dovecot
# Patch ldflags
find . -name "Makefile.am" -exec sed -i -e 's,(FUZZER_LDFLAGS),(FUZZER_LDFLAGS) -static-libtool-libs,' {} \;
./autogen.sh
./configure PANDOC=false --with-fuzzer=clang --prefix=$OUT
make -j$(nproc)
# Copy over the fuzzers
find . -name "fuzz-*" -executable -exec libtool install install -m0755 {} $OUT/ \;
cd ../pigeonhole
find . -name "Makefile.am" -exec sed -i -e 's,(FUZZER_LDFLAGS),(FUZZER_LDFLAGS) -static-libtool-libs,' {} \;
./autogen.sh
./configure --with-dovecot=../dovecot --with-fuzzer=clang --prefix=$OUT
make -j$(nproc)
# Copy over the fuzzers
find . -name "fuzz-*" -executable -exec libtool install install -m0755 {} $OUT/ \;

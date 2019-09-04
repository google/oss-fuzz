#!/bin/bash -eu
# Copyright 2019 Google Inc.
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

# build project
cd binutils-gdb
git apply ../patch.diff
./configure --disable-gdb --enable-targets=all
make MAKEINFO=true && true
mkdir fuzz
cp ../fuzz_disassemble.c fuzz/

$CC $CFLAGS -I include -I bfd -I opcodes -c fuzz/fuzz_disassemble.c -o fuzz/fuzz_disassemble.o
$CXX $CXXFLAGS fuzz/fuzz_disassemble.o -o $OUT/fuzz_disassemble -lFuzzingEngine opcodes/libopcodes.a bfd/libbfd.a libiberty/libiberty.a zlib/libz.a

# TODO build corpuses

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

# build elf tooling targets
autoreconf -i -f
./configure --enable-maintainer-mode --disable-libdebuginfod --enable-libdebuginfod=dummy --disable-debuginfod --disable-libdebuginfod

cd lib && make libeu.a && cd ..
cd libdwfl && make libdwfl.a && cd ..
cd libebl && make libebl.a && cd ..
cd backends && make libebl_backends.a && cd ..
cd libcpu && make libcpu.a && cd ..
cd libdwelf && make libdwelf.a && cd ..
cd libdw && make libdw.a known-dwarf.h && cd ..
cd libelf && make libelf.a && cd ..
cd src && cp readelf.c libreadelf.c && patch libreadelf.c libreadelf.diff && make libreadelf && cd ..

# build fuzzer
cd fuzz

mv ../src/libreadelf libreadelf.o
ar -x ../libdw/libdw.a
ar -x ../libebl/libebl.a
ar -x ../backends/libebl_backends.a
ar -x ../libcpu/libcpu.a
ar -x ../libelf/libelf.a
ar -x ../lib/libeu.a
ar -x ../libdwfl/libdwfl.a
ar -x ../libdwelf/libdwelf.a

$CXX $CXXFLAGS fuzz.cc -o $OUT/testfuzz *.o -lz -ldl -lpthread -lbz2 -llzma $LIB_FUZZING_ENGINE

# build corpus
zip -j0r $OUT/testfuzz_seed_corpus.zip corpus/*


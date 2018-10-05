#!/bin/bash -eu
# Copyright 2017 Google Inc.
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

./configure --enable-static=yes --enable-shared=no
make -j"$(nproc)"

$CXX $CXXFLAGS -std=c++11 -Ilibclamav/ \
    $SRC/clamav_scanfile_fuzzer.cc -o $OUT/clamav_scanfile_fuzzer \
    -lFuzzingEngine libclamav/.libs/libclamav.a \
    libclamav/libmspack-0.5alpha/.libs/libclammspack.a \
    -Wl,-Bstatic -lssl -lcrypto -lz -Wl,-Bdynamic -ldl

for type in ARCHIVE MAIL OLE2 PDF HTML PE ELF SWF XMLDOCS HWP3; do
    $CXX $CXXFLAGS -std=c++11 -Ilibclamav/ \
        $SRC/clamav_scanfile_fuzzer.cc \
        -o "${OUT}/clamav_scanfile_${type}_fuzzer" "-DCLAMAV_FUZZ_${type}" \
        -lFuzzingEngine libclamav/.libs/libclamav.a \
        libclamav/libmspack-0.5alpha/.libs/libclammspack.a \
        -Wl,-Bstatic -lssl -lcrypto -lz -Wl,-Bdynamic -ldl
done

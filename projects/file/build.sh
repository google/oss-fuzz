#!/bin/bash -eu
# Copyright 2016 Google Inc.
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

autoreconf -i
./configure --enable-static --enable-fsect-man5
make V=1 all

$CXX $CXXFLAGS -std=c++11 -Isrc/ \
     $SRC/magic_fuzzer.cc -o $OUT/magic_fuzzer \
     $LIB_FUZZING_ENGINE ./src/.libs/libmagic.a -l:libz.a -l:liblz4.a -l:libbz2.a -l:liblzma.a -l:libzstd.a
$CXX $CXXFLAGS -std=c++11 -Isrc/ \
     $SRC/magic_fuzzer_loaddb.cc -o $OUT/magic_fuzzer_loaddb \
     $LIB_FUZZING_ENGINE ./src/.libs/libmagic.a -l:libz.a -l:liblz4.a -l:libbz2.a -l:liblzma.a -l:libzstd.a
$CXX $CXXFLAGS -std=c++11 -Isrc/ \
     $SRC/magic_fuzzer_fd.cc -o $OUT/magic_fuzzer_fd \
     $LIB_FUZZING_ENGINE ./src/.libs/libmagic.a -l:libz.a -l:liblz4.a -l:libbz2.a -l:liblzma.a -l:libzstd.a

cp ./magic/magic.mgc $OUT/

mkdir pocs_all
find $SRC/pocs/ -type f -print0 | xargs -0 -I % mv -f % ./pocs_all

zip -j $OUT/magic_fuzzer_seed_corpus.zip ./tests/*.testfile $SRC/binary-samples/{elf,pe}-* $SRC/pocs_all

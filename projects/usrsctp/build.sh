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

cmake -Dsctp_build_programs=0 -Dsctp_debug=0 -Dsctp_invariants=1 -Dsctp_build_fuzzer=1 -DCMAKE_BUILD_TYPE=RelWithDebInfo .
make -j$(nproc)
cd fuzzer

TARGETS="fuzzer_connect fuzzer_listen fuzzer_fragment"

CORPUS="CORPUS_CONNECT CORPUS_LISTEN CORPUS_FRAGMENT"

while [ -n "$TARGETS" ]
do
        target=`echo "$TARGETS" | cut -d ' ' -f 1`
        TARGETS=`echo "$TARGETS" | sed 's/[^ ]* *\(.*\)$/\1/'`
        corpus=`echo "$CORPUS" | cut -d ' ' -f 1`
        CORPUS=`echo "$CORPUS" | sed 's/[^ ]* *\(.*\)$/\1/'`

        $CC $CFLAGS -DFUZZING_STAGE=0 -I . -I ../usrsctplib/ -c ${target}.c -o $OUT/${target}.o
        $CXX $CXXFLAGS -o $OUT/${target} $OUT/${target}.o $LIB_FUZZING_ENGINE ../usrsctplib/libusrsctp.a
        rm -f $OUT/${target}.o

        zip -jr ${target}_seed_corpus.zip ${corpus}/
        cp ${target}_seed_corpus.zip $OUT/
done

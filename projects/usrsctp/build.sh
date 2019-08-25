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

cmake -Dsctp_build_programs=0 -Dsctp_debug=0 -Dsctp_build_programs=0 -DCMAKE_BUILD_TYPE=RelWithDebInfo .
make -j$(nproc)
cd fuzzer

TARGETS="fuzzer_connected fuzzer_unconnected"

for target in $TARGETS; do
        $CC $CFLAGS -I . -I ../usrsctplib/ -c ${target}.c -o $OUT/${target}.o
        $CXX $CXXFLAGS -o $OUT/${target} $OUT/${target}.o $LIB_FUZZING_ENGINE ../usrsctplib/libusrsctp.a
        rm -f $OUT/${target}.o
done

zip -jr fuzzer_connected_seed_corpus.zip CORPUS_CONNECTED/
cp fuzzer_connected_seed_corpus.zip $OUT/

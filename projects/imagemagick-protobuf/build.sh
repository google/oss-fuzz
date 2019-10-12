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

./configure --prefix="$WORK" --disable-shared --disable-docs
make "-j$(nproc)"
make install

rm -rf genfiles && mkdir genfiles && ../LPM/external.protobuf/bin/protoc --proto_path=.. ../ops.proto --cpp_out=genfiles/

$CXX $CXXFLAGS -std=c++11 -I"$WORK/include/ImageMagick-7" \
    ../ops_fuzzer.cc genfiles/ops.pb.cc \
    -I genfiles -I ../libprotobuf-mutator/ -I ../LPM/external.protobuf/include \
    -lz \
    ../LPM/src/libfuzzer/libprotobuf-mutator-libfuzzer.a \
    ../LPM/src/libprotobuf-mutator.a ../LPM/external.protobuf/lib/libprotobuf.a \
    -DMAGICKCORE_HDRI_ENABLE=1 -DMAGICKCORE_QUANTUM_DEPTH=16 \
    "$WORK/lib/libMagick++-7.Q16HDRI.a" \
    "$WORK/lib/libMagickWand-7.Q16HDRI.a" \
    "$WORK/lib/libMagickCore-7.Q16HDRI.a" \
    $LIB_FUZZING_ENGINE \
    -o $OUT/imagemagick_ops_fuzzer

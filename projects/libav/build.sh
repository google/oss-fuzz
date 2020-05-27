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

cd libav
./configure --toolchain=clang-asan
make

for target in probe
do
    $CC $CFLAGS -I. -Iavtools/ -c $SRC/fuzz_$target.c -o $SRC/fuzz_$target.o
    $CC $CFLAGS -I. -Iavtools/ -c avtools/cmdutils.c -o $SRC/cmdutils.o
    $CXX $CXXFLAGS $SRC/fuzz_$target.o cmdutils.o -o $OUT/fuzz_$target \
    $LIB_FUZZING_ENGINE ./libavformat/libavformat.a ./libavcodec/libavcodec.a ./libavresample/libavresample.a ./libavdevice/libavdevice.a ./libavutil/libavutil.a ./libswscale/libswscale.a

./libavfilter/libavfilter.a ./libavutil/libavutil.a ./libavdevice/libavdevice.a ./libavformat/libavformat.a ./libswscale/libswscale.a ./libavcodec/libavcodec.a ./libavresample/libavresample.a
done

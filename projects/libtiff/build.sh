#!/bin/bash -eu
# Copyright 2018 Google Inc.
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

. contrib/oss-fuzz/build.sh

cp $SRC/write_fuzzer.cc $SRC/libtiff/contrib/oss-fuzz/
if [ "$ARCHITECTURE" = "i386" ]; then
    $CXX $CXXFLAGS -std=c++11 -I$WORK/include \
        $SRC/libtiff/contrib/oss-fuzz/write_fuzzer.cc -o $OUT/tiff_write_fuzzer \
        $LIB_FUZZING_ENGINE $WORK/lib/libtiffxx.a $WORK/lib/libtiff.a $WORK/lib/libz.a $WORK/lib/libjpeg.a \
        $WORK/lib/libjbig.a $WORK/lib/libjbig85.a
else
    $CXX $CXXFLAGS -std=c++11 -I$WORK/include \
        $SRC/libtiff/contrib/oss-fuzz/write_fuzzer.cc -o $OUT/tiff_write_fuzzer \
        $LIB_FUZZING_ENGINE $WORK/lib/libtiffxx.a $WORK/lib/libtiff.a $WORK/lib/libz.a $WORK/lib/libjpeg.a \
        $WORK/lib/libjbig.a $WORK/lib/libjbig85.a -Wl,-Bstatic -llzma -Wl,-Bdynamic
fi

#!/bin/bash -eu
# Copyright 2021 Google Inc.
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

export ASAN_OPTIONS="detect_leaks=0"

./configure --disable-gst --disable-x265 --disable-numa --disable-vce --disable-nvenc --disable-gtk --disable-gtk-update-checks
cd build
make

$CC $CFLAGS $LIB_FUZZING_ENGINE $SRC/fuzz_hb.c -o $OUT/fuzz_hb -mfpmath=sse -msse2 \
    -fstack-protector-strong -D_FORTIFY_SOURCE=2  -I./libhb/ -I./contrib/include \
    -I/usr/include/libxml2 -Wl,--start-group  ./libhb/libhandbrake.a \
    -L./contrib/lib /usr/lib/x86_64-linux-gnu/libass.a \
     /usr/lib/x86_64-linux-gnu/libvpx.a \
     /usr/lib/x86_64-linux-gnu/libx264.a \
    -lavformat -lavfilter -lavcodec -lavutil -lswresample -lpostproc \
    -lmp3lame -ldvdnav -ldvdread -lfribidi -lswscale -ltheoraenc \
    -ltheoradec -lvorbis -lvorbisenc -logg -lbluray -lfreetype \
    -lxml2 -lbz2 -lz -ljansson -lharfbuzz -lopus -lspeex -llzma \
    -ldav1d -lturbojpeg -lzimg -lfontconfig -lpthread -ldl -lm -Wl,--end-group

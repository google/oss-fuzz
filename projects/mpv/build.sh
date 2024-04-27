#!/bin/bash -eu
# Copyright 2024 Google LLC
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

if [[ "$ARCHITECTURE" == i386 ]]; then
  export PKG_CONFIG_PATH=/usr/local/lib/i386-linux-gnu/pkgconfig:/usr/lib/i386-linux-gnu/pkgconfig
  LIBDIR='lib/i386-linux-gnu'
  FFMPEG_BUILD_ARGS='--arch="i386" --cpu="i386" --disable-inline-asm'
else
  LIBDIR='lib/x86_64-linux-gnu'
  FFMPEG_BUILD_ARGS=''
fi

pushd $SRC/ffmpeg
./configure --cc=$CC --cxx=$CXX --ld="$CXX $CXXFLAGS" \
            --disable-shared --enable-gpl --enable-nonfree \
            --disable-programs --disable-asm --pkg-config-flags="--static" \
            $FFMPEG_BUILD_ARGS
make -j`nproc`
make install
popd

pushd $SRC/libplacebo
meson setup build -Ddefault_library=static -Dprefer_static=true --libdir $LIBDIR
meson install -C build
popd

pushd $SRC/mpv
sed -i -e "/^\s*flags += \['-fsanitize=address,undefined,fuzzer', '-fno-omit-frame-pointer'\]/d; \
          s|^\s*link_flags += \['-fsanitize=address,undefined,fuzzer', '-fno-omit-frame-pointer'\]| \
          link_flags += \['$LIB_FUZZING_ENGINE'\]|" meson.build
meson setup build -Ddefault_library=static -Dprefer_static=true \
                  -Dfuzzers=true -Dlibmpv=true -Dcplayer=false \
                  -Dc_link_args="$CXXFLAGS -lc++ -Wl,-rpath,'\$ORIGIN/lib'" \
                  --libdir $LIBDIR
meson compile -C build

cp ./build/fuzzers/fuzzer_*  $OUT/ || true
# Static lib not available, requirement pulled by libass
mkdir -p $OUT/lib/
cp /usr/$LIBDIR/libgraphite2.so.3 $OUT/lib/

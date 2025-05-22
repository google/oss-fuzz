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
  RUST_TARGET='i686-unknown-linux-gnu'
  rustup target add $RUST_TARGET
else
  LIBDIR='lib/x86_64-linux-gnu'
  FFMPEG_BUILD_ARGS=''
  RUST_TARGET='x86_64-unknown-linux-gnu'
  rustup target add $RUST_TARGET
fi

export RUSTC="rustc --target=$RUST_TARGET"

export FUZZ_INTROSPECTOR_CONFIG=$SRC/fuzz_introspector_exclusion.config
cat > $FUZZ_INTROSPECTOR_CONFIG <<EOF
FILES_TO_AVOID
ffmpeg
mpv/subprojects
mpv/build/subprojects
EOF

pushd $SRC/ffmpeg
./configure --cc=$CC --cxx=$CXX --ld="$CXX $CXXFLAGS" \
            --enable-{gpl,nonfree} \
            --disable-{asm,bsfs,doc,encoders,filters,muxers,network,programs,shared} \
            --enable-filter={sine,yuvtestsrc} \
            --pkg-config-flags="--static" \
            --disable-{debug,optimizations} \
            --optflags=-O1 \
            $FFMPEG_BUILD_ARGS
make -j`nproc`
make install
popd

# The option `-fuse-ld=gold` can't be passed via `CFLAGS` or `CXXFLAGS` because
# Meson injects `-Werror=ignored-optimization-argument` during compile tests.
# Remove the `-fuse-ld=` and let Meson handle it.
# https://github.com/mesonbuild/meson/issues/6377#issuecomment-575977919
if [[ "$CFLAGS" == *"-fuse-ld=gold"* ]]; then
    export CFLAGS="${CFLAGS//-fuse-ld=gold/}"
    export CC_LD=gold
fi
if [[ "$CXXFLAGS" == *"-fuse-ld=gold"* ]]; then
    export CXXFLAGS="${CXXFLAGS//-fuse-ld=gold/}"
    export CXX_LD=gold
fi

pushd $SRC/mpv
sed -i -e "/^\s*flags += \['-fsanitize=address,undefined,fuzzer', '-fno-omit-frame-pointer'\]/d; \
          s|^\s*link_flags += \['-fsanitize=address,undefined,fuzzer', '-fno-omit-frame-pointer'\]| \
          link_flags += \['$LIB_FUZZING_ENGINE'\]|" meson.build

meson setup build --wrap-mode=nodownload -Dbuildtype=plain -Dbackend_max_links=4 -Ddefault_library=static -Dprefer_static=true \
                  -Dfuzzers=true -Dlibmpv=true -Dcplayer=false -Dgpl=true \
                  -Duchardet=enabled -Dlcms2=enabled -Dtests=false \
                  -Dfreetype2:harfbuzz=disabled -Dfreetype2:zlib=disabled -Dfreetype2:png=disabled \
                  -Dharfbuzz:tests=disabled -Dharfbuzz:introspection=disabled -Dharfbuzz:docs=disabled \
                  -Dharfbuzz:utilities=disabled -Dfontconfig:doc=disabled -Dfontconfig:nls=disabled -Dfontconfig:xml-backend=expat \
                  -Dfontconfig:tests=disabled -Dfontconfig:tools=disabled -Dfontconfig:cache-build=disabled \
                  -Dfribidi:deprecated=false -Dfribidi:docs=false -Dfribidi:bin=false -Dfribidi:tests=false \
                  -Dlibplacebo:lcms=enabled -Dlibplacebo:xxhash=enabled -Dlibplacebo:demos=false \
                  -Dlcms2:jpeg=disabled -Dlcms2:tiff=disabled \
                  -Dlibass:fontconfig=enabled -Dlibass:asm=disabled \
                  -Dc_args="$CFLAGS" -Dcpp_args="$CXXFLAGS" \
                  -Dc_link_args="$CFLAGS" -Dcpp_link_args="$CXXFLAGS" \
                  --libdir $LIBDIR
meson compile -C build fuzzers

find ./build/fuzzers -maxdepth 1 -type f -name 'fuzzer_*' -exec mv {} "$OUT" \; -exec echo "{} -> $OUT" \;

rsync --no-compress -av rsync://samples.ffmpeg.org/samples/Matroska $SRC/matroska
zip -0 -r $OUT/fuzzer_loadfile_mkv_seed_corpus.zip $SRC/matroska -i '*.mkv' '*.mka'

#!/bin/bash -eux
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

# Disable UBSan vptr since several targets built with -fno-rtti.
export CFLAGS="$CFLAGS -fno-sanitize=vptr"
export CXXFLAGS="$CXXFLAGS -fno-sanitize=vptr"

if [[ "$CXXFLAGS" == *"-fsanitize=address"* ]]; then
    export CXXFLAGS="$CXXFLAGS -fno-sanitize-address-use-odr-indicator"
fi

if [[ "$CFLAGS" == *"-fsanitize=address"* ]]; then
    export CFLAGS="$CFLAGS -fno-sanitize-address-use-odr-indicator"
fi

if [[ "$ARCHITECTURE" == i386 ]]; then
  export CFLAGS="$CFLAGS -m32"
  export CXXFLAGS="$CXXFLAGS -m32"
fi

# Build dependencies.
export FFMPEG_DEPS_PATH=$SRC/ffmpeg_deps
mkdir -p $FFMPEG_DEPS_PATH


if [[ "$ARCHITECTURE" == i386 ]]; then
  LIBDIR='lib/i386-linux-gnu'
  export PKG_CONFIG_PATH="$FFMPEG_DEPS_PATH/$LIBDIR/pkgconfig:$FFMPEG_DEPS_PATH/lib/pkgconfig"
else
  LIBDIR='lib/x86_64-linux-gnu'
  export PKG_CONFIG_PATH="$FFMPEG_DEPS_PATH/$LIBDIR/pkgconfig:$FFMPEG_DEPS_PATH/lib/pkgconfig"
fi

# The option `-fuse-ld=gold` can't be passed via `CFLAGS` or `CXXFLAGS` because
# Meson injects `-Werror=ignored-optimization-argument` during compile tests.
# Remove the `-fuse-ld=` and let Meson handle it.
# https://github.com/mesonbuild/meson/issues/6377#issuecomment-575977919
export MESON_CFLAGS="$CFLAGS"
if [[ "$CFLAGS" == *"-fuse-ld=gold"* ]]; then
    export MESON_CFLAGS="${CFLAGS//-fuse-ld=gold/}"
    export CC_LD=gold
fi
export MESON_CXXFLAGS="$CXXFLAGS"
if [[ "$CXXFLAGS" == *"-fuse-ld=gold"* ]]; then
    export MESON_CXXFLAGS="${CXXFLAGS//-fuse-ld=gold/}"
    export CXX_LD=gold
fi

meson_install() {
  cd $SRC/$1
  CFLAGS="$MESON_CFLAGS" CXXFLAGS="$MESON_CXXFLAGS" \
  meson setup build -Dprefix="$FFMPEG_DEPS_PATH" -Ddefault_library=static -Dprefer_static=true \
                    --wrap-mode=nofallback --libdir "$LIBDIR" ${2:-}
  meson compile -C build
  meson install -C build
}

meson_install bzip2

cd $SRC/zlib
./configure --prefix="$FFMPEG_DEPS_PATH" --enable-static --disable-shared
make clean
make -j$(nproc)
make install

cd $SRC/libxml2
./autogen.sh --prefix="$FFMPEG_DEPS_PATH" --enable-static \
      --without-debug --without-ftp --without-http \
      --without-legacy --without-python
make clean
make -j$(nproc)
make install

meson_install freetype "-Dharfbuzz=disabled"
meson_install fribidi "-Ddocs=false -Dtests=false"
meson_install harfbuzz "-Ddocs=disabled -Dtests=disabled"
meson_install fontconfig "-Dtests=disabled -Dtools=disabled"

cd $SRC/libass
./autogen.sh
./configure --prefix="$FFMPEG_DEPS_PATH" --enable-static --disable-shared --disable-asm
make -j$(nproc)
make install

cd $SRC
bzip2 -f -d alsa-lib-*
tar xf alsa-lib-*
rm alsa-lib-*.tar
cd alsa-lib-*
./configure --prefix="$FFMPEG_DEPS_PATH" --enable-static --disable-shared
make clean
make -j$(nproc) all
make install

cd $SRC/fdk-aac
autoreconf -fiv
CXXFLAGS="$CXXFLAGS -fno-sanitize=shift-base,signed-integer-overflow" \
./configure --prefix="$FFMPEG_DEPS_PATH" --disable-shared
make clean
make -j$(nproc) all
make install

cd $SRC/libvpx
if [[ "$SANITIZER" == "memory" ]] || [[ "$FUZZING_ENGINE" == "centipede" ]]; then
      TARGET="--target=generic-gnu"
elif [[ "$ARCHITECTURE" == i386 ]]; then
      TARGET="--target=x86-linux-gcc"
else
      TARGET=""
fi

LDFLAGS="$CXXFLAGS" ./configure --prefix="$FFMPEG_DEPS_PATH" \
        --disable-docs --disable-examples --disable-tools --disable-unit-tests \
        --enable-vp9-highbitdepth \
        --size-limit=12288x12288 \
        --extra-cflags="-DVPX_MAX_ALLOCABLE_MEMORY=1073741824" \
        $TARGET

make clean
make -j$(nproc) all
make install

cd $SRC/ogg
./autogen.sh
./configure --prefix="$FFMPEG_DEPS_PATH" --enable-static --disable-crc
make clean
make -j$(nproc)
make install

cd $SRC/opus
./autogen.sh
./configure --prefix="$FFMPEG_DEPS_PATH" --enable-static
make clean
make -j$(nproc) all
make install

cd $SRC/theora
if [[ "$ARCHITECTURE" == i386 ]]; then

      THEORA_BUILD_ARGS='--disable-asm'
else
      THEORA_BUILD_ARGS=''
fi
# theora requires ogg, need to pass its location to the "configure" script.
CFLAGS="$CFLAGS -fPIC" LDFLAGS="-L$FFMPEG_DEPS_PATH/lib/" \
      CPPFLAGS="$CXXFLAGS -I$FFMPEG_DEPS_PATH/include/" \
      LD_LIBRARY_PATH="$FFMPEG_DEPS_PATH/lib/" \
      ./autogen.sh
./configure --with-ogg="$FFMPEG_DEPS_PATH" --prefix="$FFMPEG_DEPS_PATH" \
      --enable-static --disable-examples $THEORA_BUILD_ARGS
make clean
make -j$(nproc)
make install

cd $SRC/vorbis
./autogen.sh
./configure --prefix="$FFMPEG_DEPS_PATH" --enable-static
make clean
make -j$(nproc)
make install

# Remove shared libraries to avoid accidental linking against them.
rm $FFMPEG_DEPS_PATH/lib/*.so
rm $FFMPEG_DEPS_PATH/lib/*.so.*

# Build ffmpeg.
cd $SRC/ffmpeg
if [[ "$ARCHITECTURE" == i386 ]]; then

      FFMPEG_BUILD_ARGS='--arch="i386" --cpu="i386" --disable-inline-asm --disable-asm'
else
      FFMPEG_BUILD_ARGS=''
fi

if [ "$SANITIZER" = "memory" ] || [ "$FUZZING_ENGINE" = "centipede" ]; then
  FFMPEG_BUILD_ARGS="$FFMPEG_BUILD_ARGS --disable-asm"
fi

./configure \
        --cc=$CC --cxx=$CXX --ld="$CXX $CXXFLAGS -std=c++11" \
        --extra-cflags="-I$FFMPEG_DEPS_PATH/include" \
        --extra-ldflags="-L$FFMPEG_DEPS_PATH/lib" \
        --prefix="$FFMPEG_DEPS_PATH" \
        --pkg-config-flags="--static" \
        --enable-ossfuzz \
        --libfuzzer=$LIB_FUZZING_ENGINE \
        --optflags=-O1 \
        --enable-gpl \
        --enable-nonfree \
        --enable-libass \
        --enable-libfdk-aac \
        --enable-libfreetype \
        --enable-libopus \
        --enable-libtheora \
        --enable-libvorbis \
        --enable-libvpx \
        --enable-libxml2 \
        --enable-nonfree \
        --disable-libdrm \
        --disable-muxers \
        --disable-protocols \
        --disable-demuxer=rtp,rtsp,sdp \
        --disable-devices \
        --disable-shared \
        --disable-doc \
        --disable-programs \
        $FFMPEG_BUILD_ARGS
make clean
make -j$(nproc) install

# Download test samples, will be used as seed corpus.
# DISABLED.
# TODO: implement a better way to maintain a minimized seed corpora
# for all targets. As of 2017-05-04 now the combined size of corpora
# is too big for ClusterFuzz (over 10Gb compressed data).
export TEST_SAMPLES_PATH=$SRC/ffmpeg/fate-suite/
make fate-rsync SAMPLES=$TEST_SAMPLES_PATH

rsync -av rsync://samples.ffmpeg.org/samples/avi/ffv1/testset/ $SRC/ffmpeg/ffv1testset

# Build the fuzzers.
cd $SRC/ffmpeg

FUZZ_TARGET_SOURCE=$SRC/ffmpeg/tools/target_dec_fuzzer.c

export TEMP_VAR_CODEC="AV_CODEC_ID_H264"
export TEMP_VAR_CODEC_TYPE="VIDEO"

CONDITIONALS=$(grep 'BSF 1$' config_components.h | sed 's/#define CONFIG_\(.*\)_BSF 1/\1/')
if [ -n "${OSS_FUZZ_CI-}" ]; then
      # When running in CI, check the first targets only to save time and disk space
      CONDITIONALS=(${CONDITIONALS[@]:0:2})
fi
for c in $CONDITIONALS; do
      fuzzer_name=ffmpeg_BSF_${c}_fuzzer
      symbol=$(echo $c | sed "s/.*/\L\0/")
      echo -en "[libfuzzer]\nmax_len = 1000000\n" >$OUT/${fuzzer_name}.options
      make tools/target_bsf_${symbol}_fuzzer
      mv tools/target_bsf_${symbol}_fuzzer $OUT/${fuzzer_name}
done

# Build fuzzers for decoders.
CONDITIONALS=$(grep 'DECODER 1$' config_components.h | sed 's/#define CONFIG_\(.*\)_DECODER 1/\1/')
if [ -n "${OSS_FUZZ_CI-}" ]; then
      # When running in CI, check the first targets only to save time and disk space
      CONDITIONALS=(${CONDITIONALS[@]:0:2})
fi
for c in $CONDITIONALS; do
      fuzzer_name=ffmpeg_AV_CODEC_ID_${c}_fuzzer
      symbol=$(echo $c | sed "s/.*/\L\0/")
      echo -en "[libfuzzer]\nmax_len = 1000000\n" >$OUT/${fuzzer_name}.options
      make tools/target_dec_${symbol}_fuzzer
      mv tools/target_dec_${symbol}_fuzzer $OUT/${fuzzer_name}
done

# Build fuzzers for encoders
CONDITIONALS=$(grep 'ENCODER 1$' config_components.h | sed 's/#define CONFIG_\(.*\)_ENCODER 1/\1/')
if [ -n "${OSS_FUZZ_CI-}" ]; then
      # When running in CI, check the first targets only to save time and disk space
      CONDITIONALS=(${CONDITIONALS[@]:0:2})
fi

for c in $CONDITIONALS; do
      fuzzer_name=ffmpeg_AV_CODEC_ID_${c}_fuzzer
      symbol=$(echo $c | sed "s/.*/\L\0/")
      echo -en "[libfuzzer]\nmax_len = 1000000\n" >$OUT/${fuzzer_name}.options
      make tools/target_enc_${symbol}_fuzzer
      mv tools/target_enc_${symbol}_fuzzer $OUT/${fuzzer_name}
done


# Build fuzzer for sws
fuzzer_name=ffmpeg_SWS_fuzzer
echo -en "[libfuzzer]\nmax_len = 1000000\n" >$OUT/${fuzzer_name}.options
make tools/target_sws_fuzzer
mv tools/target_sws_fuzzer $OUT/${fuzzer_name}

# Build fuzzer for swr
fuzzer_name=ffmpeg_SWR_fuzzer
echo -en "[libfuzzer]\nmax_len = 1000000\n" >$OUT/${fuzzer_name}.options
make tools/target_swr_fuzzer
mv tools/target_swr_fuzzer $OUT/${fuzzer_name}

# Build fuzzer for demuxer
fuzzer_name=ffmpeg_DEMUXER_fuzzer
echo -en "[libfuzzer]\nmax_len = 1000000\n" >$OUT/${fuzzer_name}.options
make tools/target_dem_fuzzer
mv tools/target_dem_fuzzer $OUT/${fuzzer_name}

# We do not need raw reference files for the muxer
rm $(find fate-suite -name '*.s16')
rm $(find fate-suite -name '*.dec')
rm $(find fate-suite -name '*.pcm')

zip -r $OUT/${fuzzer_name}_seed_corpus.zip fate-suite
zip -r $OUT/ffmpeg_AV_CODEC_ID_HEVC_fuzzer_seed_corpus.zip fate-suite/hevc fate-suite/hevc-conformance
zip -r $OUT/ffmpeg_AV_CODEC_ID_FFV1_fuzzer_seed_corpus.zip ffv1testset

# Build fuzzer for demuxer fed at IO level
fuzzer_name=ffmpeg_IO_DEMUXER_fuzzer
make tools/target_io_dem_fuzzer
mv tools/target_io_dem_fuzzer $OUT/${fuzzer_name}

#Build fuzzers for individual demuxers
./configure \
        --cc=$CC --cxx=$CXX --ld="$CXX $CXXFLAGS -std=c++11" \
        --extra-cflags="-I$FFMPEG_DEPS_PATH/include" \
        --extra-ldflags="-L$FFMPEG_DEPS_PATH/lib" \
        --prefix="$FFMPEG_DEPS_PATH" \
        --pkg-config-flags="--static" \
        --enable-ossfuzz \
        --libfuzzer=$LIB_FUZZING_ENGINE \
        --optflags=-O1 \
        --enable-gpl \
        --enable-libxml2 \
        --disable-libdrm \
        --disable-muxers \
        --disable-protocols \
        --disable-devices \
        --disable-shared \
        --disable-encoders \
        --disable-filters \
        --disable-muxers \
        --disable-parsers \
        --disable-decoders \
        --disable-hwaccels \
        --disable-bsfs \
        --disable-vaapi \
        --disable-vdpau \
        --disable-v4l2_m2m \
        --disable-cuda_llvm \
        --enable-demuxers \
        --disable-demuxer=rtp,rtsp,sdp \
        --disable-doc \
        --disable-programs \
        $FFMPEG_BUILD_ARGS

CONDITIONALS=$(grep 'DEMUXER 1$' config_components.h | sed 's/#define CONFIG_\(.*\)_DEMUXER 1/\1/')
if [ -n "${OSS_FUZZ_CI-}" ]; then
      # When running in CI, check the first targets only to save time and disk space
      CONDITIONALS=(${CONDITIONALS[@]:0:2})
fi

for c in $CONDITIONALS; do
      fuzzer_name=ffmpeg_dem_${c}_fuzzer
      symbol=$(echo $c | sed "s/.*/\L\0/")
      make tools/target_dem_${symbol}_fuzzer
      mv tools/target_dem_${symbol}_fuzzer $OUT/${fuzzer_name}
done

# Find relevant corpus in test samples and archive them for every fuzzer.
#cd $SRC
#python group_seed_corpus.py $TEST_SAMPLES_PATH $OUT/

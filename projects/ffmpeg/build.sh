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
  meson install -C build
}

meson_install bzip2

cd $SRC/zlib
./configure --prefix="$FFMPEG_DEPS_PATH" --enable-static --disable-shared
make -j$(nproc) install

cd $SRC/libxml2
./autogen.sh --prefix="$FFMPEG_DEPS_PATH" --enable-static \
      --without-debug --without-ftp --without-http \
      --without-legacy --without-python
make -j$(nproc) install
meson_install freetype "-Dharfbuzz=disabled"
meson_install fribidi "-Ddocs=false -Dtests=false"
meson_install harfbuzz "-Ddocs=disabled -Dtests=disabled"
meson_install fontconfig "-Dtests=disabled -Dtools=disabled"

cd $SRC/libass
./autogen.sh
./configure --prefix="$FFMPEG_DEPS_PATH" --enable-static --disable-shared --disable-asm
make -j$(nproc) install

cd $SRC
bzip2 -f -d alsa-lib-*
tar xf alsa-lib-*
rm alsa-lib-*.tar
cd alsa-lib-*
./configure --prefix="$FFMPEG_DEPS_PATH" --enable-static --disable-shared
make -j$(nproc) install

cd $SRC/fdk-aac
autoreconf -fiv
CXXFLAGS="$CXXFLAGS -fno-sanitize=shift-base,signed-integer-overflow" \
./configure --prefix="$FFMPEG_DEPS_PATH" --disable-shared
make -j$(nproc) install

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

make -j$(nproc) install

cd $SRC/ogg
./autogen.sh
./configure --prefix="$FFMPEG_DEPS_PATH" --enable-static --disable-crc
make -j$(nproc) install

cd $SRC/opus
./autogen.sh
./configure --prefix="$FFMPEG_DEPS_PATH" --enable-static
make -j$(nproc) install

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
make -j$(nproc) install

cd $SRC/vorbis
./autogen.sh
./configure --prefix="$FFMPEG_DEPS_PATH" --enable-static
make -j$(nproc) install

# Remove shared libraries to avoid accidental linking against them.
rm $FFMPEG_DEPS_PATH/lib/*.so
rm $FFMPEG_DEPS_PATH/lib/*.so.*

# Build ffmpeg.
cd $SRC/ffmpeg
if [[ "$ARCHITECTURE" == i386 ]]; then

      FFMPEG_BUILD_ARGS='--arch="i386" --cpu="i386" --disable-inline-asm --disable-asm'
else
      FFMPEG_BUILD_ARGS='--disable-asm'
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
        --enable-demuxers \
        --samples=fate-suite/ \
        $FFMPEG_BUILD_ARGS

# Download test samples, will be used as seed corpus.
# DISABLED.
# TODO: implement a better way to maintain a minimized seed corpora
# for all targets. As of 2017-05-04 now the combined size of corpora
# is too big for ClusterFuzz (over 10Gb compressed data).
export TEST_SAMPLES_PATH=$SRC/ffmpeg/fate-suite/
make fate-rsync SAMPLES=$TEST_SAMPLES_PATH

if [[ -n ${CAPTURE_REPLAY_SCRIPT-} ]]; then
  exit 0
fi

rsync -av rsync://samples.ffmpeg.org/samples/avi/ffv1/testset/ $SRC/ffmpeg/ffv1testset

# Build the fuzzers.
cd $SRC/ffmpeg

FUZZ_TARGET_SOURCE=$SRC/ffmpeg/tools/target_dec_fuzzer.c

export TEMP_VAR_CODEC="AV_CODEC_ID_H264"
export TEMP_VAR_CODEC_TYPE="VIDEO"

declare -a BSF_TARGETS=()
declare -a BSF_FUZZER_NAMES=()
declare -a DECODER_TARGETS=()
declare -a DECODER_FUZZER_NAMES=()
declare -a ENCODER_TARGETS=()
declare -a ENCODER_FUZZER_NAMES=()

# Collect bitstream filters targets
CONDITIONALS=$(grep 'BSF 1$' config_components.h | sed 's/#define CONFIG_\(.*\)_BSF 1/\1/')
if [ -n "${OSS_FUZZ_CI-}" ]; then
      # When running in CI, check the first targets only to save time and disk space
      CONDITIONALS=(${CONDITIONALS[@]:0:2})
fi
for c in $CONDITIONALS; do
      fuzzer_name=$($SRC/name_mappings.py binary_name bsf ${c})
      symbol=$(echo $c | sed "s/.*/\L\0/")
      BSF_TARGETS+=("tools/target_bsf_${symbol}_fuzzer")
      BSF_FUZZER_NAMES+=("${fuzzer_name}")
done

# Collect decoder targets
CONDITIONALS=$(grep 'DECODER 1$' config_components.h | sed 's/#define CONFIG_\(.*\)_DECODER 1/\1/')
if [ -n "${OSS_FUZZ_CI-}" ]; then
      # When running in CI, check the first targets only to save time and disk space
      CONDITIONALS=(${CONDITIONALS[@]:0:2})
fi
for c in $CONDITIONALS; do
      fuzzer_name=$($SRC/name_mappings.py binary_name decoder ${c})
      symbol=$(echo $c | sed "s/.*/\L\0/")
      DECODER_TARGETS+=("tools/target_dec_${symbol}_fuzzer")
      DECODER_FUZZER_NAMES+=("${fuzzer_name}")
done

# Collect encoder targets
CONDITIONALS=$(grep 'ENCODER 1$' config_components.h | sed 's/#define CONFIG_\(.*\)_ENCODER 1/\1/')
if [ -n "${OSS_FUZZ_CI-}" ]; then
      # When running in CI, check the first targets only to save time and disk space
      CONDITIONALS=(${CONDITIONALS[@]:0:2})
fi
for c in $CONDITIONALS; do
      fuzzer_name=$($SRC/name_mappings.py binary_name encoder ${c})
      symbol=$(echo $c | sed "s/.*/\L\0/")
      ENCODER_TARGETS+=("tools/target_enc_${symbol}_fuzzer")
      ENCODER_FUZZER_NAMES+=("${fuzzer_name}")
done

OTHER_TARGETS=("tools/target_sws_fuzzer" "tools/target_swr_fuzzer" "tools/target_dem_fuzzer" "tools/target_io_dem_fuzzer")
ALL_TARGETS=("${BSF_TARGETS[@]}" "${DECODER_TARGETS[@]}" "${ENCODER_TARGETS[@]}" "${OTHER_TARGETS[@]}")
if [ ${#ALL_TARGETS[@]} -eq 0 ]; then
      echo "ERROR: No targets found to build!" >&2
      exit 1
fi
make -j$(nproc) "${ALL_TARGETS[@]}"

for i in "${!BSF_TARGETS[@]}"; do
      echo -en "[libfuzzer]\nmax_len = 1000000\n" >$OUT/${BSF_FUZZER_NAMES[$i]}.options
      mv ${BSF_TARGETS[$i]} $OUT/${BSF_FUZZER_NAMES[$i]}
done

for i in "${!DECODER_TARGETS[@]}"; do
      echo -en "[libfuzzer]\nmax_len = 1000000\n" >$OUT/${DECODER_FUZZER_NAMES[$i]}.options
      mv ${DECODER_TARGETS[$i]} $OUT/${DECODER_FUZZER_NAMES[$i]}
done

for i in "${!ENCODER_TARGETS[@]}"; do
      echo -en "[libfuzzer]\nmax_len = 1000000\n" >$OUT/${ENCODER_FUZZER_NAMES[$i]}.options
      mv ${ENCODER_TARGETS[$i]} $OUT/${ENCODER_FUZZER_NAMES[$i]}
done

# Move fuzzer for sws
fuzzer_name=$($SRC/name_mappings.py binary_name other SWS)
echo -en "[libfuzzer]\nmax_len = 1000000\n" >$OUT/${fuzzer_name}.options
mv tools/target_sws_fuzzer $OUT/${fuzzer_name}

# Move fuzzer for swr
fuzzer_name=$($SRC/name_mappings.py binary_name other SWR)
echo -en "[libfuzzer]\nmax_len = 1000000\n" >$OUT/${fuzzer_name}.options
mv tools/target_swr_fuzzer $OUT/${fuzzer_name}

# Move fuzzer for demuxer
fuzzer_name=$($SRC/name_mappings.py binary_name other DEM)
echo -en "[libfuzzer]\nmax_len = 1000000\n" >$OUT/${fuzzer_name}.options
mv tools/target_dem_fuzzer $OUT/${fuzzer_name}

# We do not need raw reference files for the muxer
rm $(find fate-suite -name '*.s16')
rm $(find fate-suite -name '*.dec')
rm $(find fate-suite -name '*.pcm')

zip -r $OUT/${fuzzer_name}_seed_corpus.zip fate-suite
zip -r $OUT/ffmpeg_AV_CODEC_ID_HEVC_fuzzer_seed_corpus.zip fate-suite/hevc fate-suite/hevc-conformance
zip -r $OUT/ffmpeg_AV_CODEC_ID_FFV1_fuzzer_seed_corpus.zip ffv1testset

# Build fuzzer for demuxer fed at IO level
fuzzer_name=$($SRC/name_mappings.py binary_name other IO_DEM)
mv tools/target_io_dem_fuzzer $OUT/${fuzzer_name}

# Clean before reconfiguring for demuxers
make distclean

# Reduce size of demuxer fuzzers by disabling various components.
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

declare -a DEMUXER_TARGETS=()
declare -a DEMUXER_FUZZER_NAMES=()

CONDITIONALS=$(grep 'DEMUXER 1$' config_components.h | sed 's/#define CONFIG_\(.*\)_DEMUXER 1/\1/')
if [ -n "${OSS_FUZZ_CI-}" ]; then
      # When running in CI, check the first targets only to save time and disk space
      CONDITIONALS=(${CONDITIONALS[@]:0:2})
fi

for c in $CONDITIONALS; do
      fuzzer_name=$($SRC/name_mappings.py binary_name demuxer ${c})
      symbol=$(echo $c | sed "s/.*/\L\0/")
      DEMUXER_TARGETS+=("tools/target_dem_${symbol}_fuzzer")
      DEMUXER_FUZZER_NAMES+=("${fuzzer_name}")
done

if [ ${#DEMUXER_TARGETS[@]} -eq 0 ]; then
      echo "ERROR: No demuxer targets found to build!" >&2
      exit 1
fi
make -j$(nproc) "${DEMUXER_TARGETS[@]}"

for i in "${!DEMUXER_TARGETS[@]}"; do
      mv ${DEMUXER_TARGETS[$i]} $OUT/${DEMUXER_FUZZER_NAMES[$i]}
done

# Find relevant corpus in test samples and archive them for every fuzzer.
#cd $SRC
#python group_seed_corpus.py $TEST_SAMPLES_PATH $OUT/

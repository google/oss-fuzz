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

if [ "$SANITIZER" = "coverage" ]
then
  touch $OUT/exit
  exit 0
fi

source $HOME/.cargo/env

# Case-sensitive names of internal Firefox fuzzing targets. Edit to add more.
FUZZ_TARGETS=(
  ContentSecurityPolicyParser
  FeaturePolicyParser
  # WebRTC
  SdpParser
  StunParser
  # Image
  ImageGIF
  ImageICO
  ImageBMP
  # Demuxing
  MediaADTS
  MediaFlac
  MediaMP3
  MediaOgg
  MediaWebM
  # MediaWAV disabled due to frequent OOMs
)

# Firefox object (build) directory and configuration file.
export MOZ_OBJDIR=$WORK/obj-fuzz
export MOZCONFIG=$SRC/mozconfig.$SANITIZER

# Without this, a host tool used during Rust part of the build will fail
export ASAN_OPTIONS="detect_leaks=0"

# Install remaining dependencies.
export SHELL=/bin/bash

rustup default nightly

./mach --no-interactive bootstrap --application-choice browser

# Skip patches for now
rm tools/fuzzing/libfuzzer/patches/*.patch
touch tools/fuzzing/libfuzzer/patches/dummy.patch

# Update internal libFuzzer.
(cd tools/fuzzing/libfuzzer && ./clone_libfuzzer.sh HEAD)

# Build!
./mach build
./mach gtest buildbutdontrun

# Packages Firefox only to immediately extract the archive. Some files are
# replaced with gtest-variants, which is required by the fuzzing interface.
# Weighs in shy of 1GB afterwards. About double for coverage builds.
./mach package
tar -xf $MOZ_OBJDIR/dist/firefox*bz2 -C $OUT
cp -L $MOZ_OBJDIR/dist/bin/gtest/libxul.so $OUT/firefox
cp $OUT/firefox/dependentlibs.list $OUT/firefox/dependentlibs.list.gtest

# Get absolute paths of the required system libraries.
LIBRARIES=$({
  xargs -I{} ldd $OUT/firefox/{} | gawk '/=> [/]/ {print $3}' | sort -u
} < $OUT/firefox/dependentlibs.list)

# Copy libraries. Less than 50MB total.
mkdir -p $OUT/lib
for LIBRARY in $LIBRARIES; do cp -L $LIBRARY $OUT/lib; done

# Build a wrapper binary for each target to set environment variables.
for FUZZ_TARGET in ${FUZZ_TARGETS[@]}
do
  $CC $CFLAGS -O0 \
    -DFUZZ_TARGET=$FUZZ_TARGET \
    $SRC/target.c -o $OUT/$FUZZ_TARGET
done

cp $SRC/*.options $OUT

# SdpParser
find media/webrtc -iname "*.sdp" \
  -type f -exec zip -qu $OUT/SdpParser_seed_corpus.zip "{}" \;
cp $SRC/fuzzdata/dicts/sdp.dict $OUT/SdpParser.dict

# StunParser
find media/webrtc -iname "*.stun" \
  -type f -exec zip -qu $OUT/StunParser_seed_corpus.zip "{}" \;
cp $SRC/fuzzdata/dicts/stun.dict $OUT/StunParser.dict

# ImageGIF
zip -rj $OUT/ImageGIF_seed_corpus.zip $SRC/fuzzdata/samples/gif
cp $SRC/fuzzdata/dicts/gif.dict $OUT/ImageGIF.dict

# ImageICO
zip -rj $OUT/ImageICO_seed_corpus.zip $SRC/fuzzdata/samples/ico

# ImageBMP
zip -rj $OUT/ImageBMP_seed_corpus.zip $SRC/fuzzdata/samples/bmp

# MediaADTS
zip -rj $OUT/MediaADTS_seed_corpus.zip $SRC/fuzzdata/samples/aac

# MediaFlac
zip -rj $OUT/MediaFlac_seed_corpus.zip $SRC/fuzzdata/samples/flac

# MediaMP3
zip -rj $OUT/MediaMP3_seed_corpus.zip $SRC/fuzzdata/samples/mp3

# MediaOgg
zip -rj $OUT/MediaOgg_seed_corpus.zip $SRC/fuzzdata/samples/ogg

# MediaWebM
zip -rj $OUT/MediaWebM_seed_corpus.zip $SRC/fuzzdata/samples/webm

# MediaWAV
# zip -rj $OUT/MediaWAV_seed_corpus.zip $SRC/fuzzdata/samples/wav

#!/bin/bash -eu
# Copyright 2021 Google LLC
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

# Build dependencies without instrumentation
CFLAGS_SAVE="$CFLAGS"
CXXFLAGS_SAVE="$CXXFLAGS"
unset CFLAGS
unset CXXFLAGS
export AFL_NOOPT=1

# But we need libc++
export CXXFLAGS="-stdlib=libc++"

# theora (>=1.2) now requires autoconf >=2.71, but the OSS-Fuzz base image
# (Ubuntu 20.04) ships autoconf 2.69. Build a newer autoconf locally via
# VLC's extras/tools and prepend it to PATH so contrib autoreconf calls find it.
(cd extras/tools && ./bootstrap && make -j$(nproc) .autoconf)
export PATH="$SRC/vlc/extras/tools/build/bin:$PATH"

mkdir contrib/contrib-build
cd contrib/contrib-build
../bootstrap

# Disable X11/xlib in FFmpeg to avoid runtime dependency on libX11
sed -i '/--target-os=linux --enable-pic/a FFMPEGCONF += --disable-xlib --disable-libxcb --disable-libxcb-shm --disable-libxcb-xfixes --disable-libxcb-shape --disable-x86asm' ../src/ffmpeg/rules.mak

# VPX's configure uses the raw 'ld' linker for its toolchain link test.
# When objects are compiled with -fsanitize=address, raw ld cannot resolve
# the ASan runtime symbols, failing with "Toolchain is unable to link
# executables". Fix: propagate sanitizer CFLAGS into LDFLAGS and override LD
# to use the compiler driver (clang/CC), which automatically links the correct
# sanitizer runtimes.
sed -i 's|VPX_LDFLAGS := $(LDFLAGS)|VPX_LDFLAGS = $(LDFLAGS) $(filter -fsanitize%,$(CFLAGS))|' ../src/vpx/rules.mak
sed -i 's|LDFLAGS="$(VPX_LDFLAGS)" CROSS=$(VPX_CROSS)|LDFLAGS="$(VPX_LDFLAGS)" LD=$(CC) CROSS=$(VPX_CROSS)|' ../src/vpx/rules.mak

make V=1 -j$(nproc) \
    .flac \
    .libxml2 \
    .ffmpeg

cd ../../

# Resume instrumentation
export CFLAGS="${CFLAGS_SAVE}"
export CXXFLAGS="${CXXFLAGS_SAVE}"
# Disable asserts under ASAN to let the fuzzer find deeper bugs past debug checks
if [ "$SANITIZER" = "address" ]; then
    export CFLAGS="$CFLAGS -DNDEBUG"
    export CXXFLAGS="$CXXFLAGS -DNDEBUG"
fi
unset AFL_NOOPT

# Build various contribs with instrumentation
cd contrib/contrib-build
make V=1 -j$(nproc) \
    .theora \
    .dav1d \
    .vpx \
    .mpg123 \
    .ebml \
    .matroska \
    .ogg \
    .opus \
    .vorbis \
    .speex \
    .speexdsp \
    .dvbpsi
cd ../../

# Use OSS-Fuzz environment rather than hardcoded setup.
sed -i 's/-fsanitize-coverage=trace-pc-guard//g' ./configure.ac
sed -i 's/-fsanitize-coverage=trace-cmp//g' ./configure.ac
sed -i 's/-fsanitize-coverage=trace-pc//g' ./configure.ac
sed -i 's/-lFuzzer//g'  ./configure.ac

# Use default -lc++
sed -i 's/-lstdc++ //g' ./configure.ac
sed -i 's/-lstdc++/$(NULL)/g' ./test/Makefile.am

sed -i 's/..\/..\/lib\/libvlc_internal.h/lib\/libvlc_internal.h/g' ./test/src/input/decoder.c

# Add extra codec, packetizer, and demux modules for broader fuzzing coverage.
# See fuzzing-modules.patch for the actual changes.
patch -p1 < $SRC/fuzzing-modules.patch

# clang is used to link the binary since there are no cpp sources (but we have
# cpp modules), force clang++ usage
touch ./test/dummy.cpp

# Rework implicit RULEs so that the final sed add dummy.cpp
RULE=vlc_demux_libfuzzer
RULE_SOURCES="${RULE}_SOURCES = vlc-demux-libfuzzer.c"
sed -i "s/${RULE}_LDADD/${RULE_SOURCES}\n${RULE}_LDADD/g" ./test/Makefile.am
RULE=vlc_demux_run
RULE_SOURCES="${RULE}_SOURCES = vlc-demux-run.c"
sed -i "s/${RULE}_LDADD/${RULE_SOURCES}\n${RULE}_LDADD/g" ./test/Makefile.am

# Add dummy.cpp to all rules
sed -i 's/_SOURCES = /_SOURCES = dummy.cpp /g' ./test/Makefile.am

# Ensure that we compile with the correct link flags.
RULE="vlc_demux_libfuzzer_LDADD"
FUZZ_LDFLAGS="vlc_demux_libfuzzer_LDFLAGS=\${LIB_FUZZING_ENGINE}"
sed -i "s/${RULE}/${FUZZ_LDFLAGS}\n${RULE}/g" ./test/Makefile.am

RULE="vlc_demux_dec_libfuzzer_LDADD"
FUZZ_LDFLAGS="vlc_demux_dec_libfuzzer_LDFLAGS=\${LIB_FUZZING_ENGINE}"
sed -i "s/${RULE}/${FUZZ_LDFLAGS}\n${RULE}/g" ./test/Makefile.am

./bootstrap

./configure --disable-lua \
            --disable-nls \
            --disable-shared \
            --enable-static \
            --enable-vlc=no \
            --disable-xcb \
            --disable-alsa \
            --disable-libva \
            --with-libfuzzer
make V=1 -j$(nproc)

cp ./test/vlc-demux-dec-libfuzzer $OUT/

# Generate structured seeds + libFuzzer dictionaries for the demux/codec
# fuzz targets that either had no dedicated corpus or whose upstream seeds
# fail to exercise the target code. See generate_seeds.py for per-target
# rationale; the script writes:
#   seeds/{ts,ps,heif,rawdv,vc1,cdg,mus,mpgv}/* and a CEA-708 SEI seed
#   appended to the upstream seeds/h264/ corpus, plus matching dictionaries.
python3 $SRC/generate_seeds.py fuzz-corpus

# Prepare for removing sdp.dict without breaking the build
rm fuzz-corpus/dictionaries/sdp.dict || true
find fuzz-corpus/dictionaries -name "*dict" -exec cat {} \; -exec echo "" \; >> $OUT/vlc-demux-dec-libfuzzer.dict
# Strip inline comments that some upstream dict files (e.g. ty.dict) append after
# token entries (e.g. "\x00\x00\x01\xB3"  # sequence_header_code).
# libFuzzer's ParseDictionaryFile rejects such lines, breaking the generic harness.
sed -i 's/^\("[^"]*"\)[[:space:]]*#.*/\1/' $OUT/vlc-demux-dec-libfuzzer.dict

for i in fuzz-corpus/seeds/* fuzz-corpus/dictionaries/*.dict
do
    target=`basename "$i" .dict`
    outfile="$OUT/vlc-demux-dec-libfuzzer"
    # the target will be selected from the command name
    outfile_target="$outfile-$target"

    # Copy dict or seeds
    if [ -f "$i" ]; then
        cp "$i" "${outfile_target}.dict"
    else
        zip -jr "${outfile_target}_seed_corpus.zip" "$i"/*
    fi

    # Create one binary per target
    cp "$outfile" "$outfile_target"
done

# Write an options file to disable leak for the general harness
echo -e "[libfuzzer]\ndetect_leaks=0" > $OUT/vlc-demux-dec-libfuzzer.options

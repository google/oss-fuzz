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

mkdir contrib/contrib-build
cd contrib/contrib-build
../bootstrap

# Disable X11/xlib in FFmpeg to avoid runtime dependency on libX11
sed -i '/--target-os=linux --enable-pic/a FFMPEGCONF += --disable-xlib --disable-libxcb --disable-libxcb-shm --disable-libxcb-xfixes --disable-libxcb-shape --disable-x86asm' ../src/ffmpeg/rules.mak

make V=1 -j$(nproc) \
    .matroska \
    .ogg \
    .libxml2 \
    .flac \
    .opus \
    .vorbis \
    .speex \
    .speexdsp \
    .theora \
    .dav1d \
    .vpx \
    .mpg123 \
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

# Build dvbpsi and mpcdec with full sanitizer/coverage instrumentation so that
# bugs in these parsing libraries are detected when the fuzzers exercise them.
cd contrib/contrib-build
make V=1 -j$(nproc) \
    .dvbpsi \
    .mpcdec
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

# Register the MPC demux module in the static module list (the module is linked
# via fuzzing-modules.patch but also needs to be in the PLUGINS macro).
sed -i 's/f(demux_ogg)/f(demux_mpc) \\\n    f(demux_ogg)/' ./test/src/input/demux-run.c

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

# Add MPEG-I/II video ES fuzzer target (mpgv.c) which lacks a dedicated corpus.
# The mpgv module is linked via fuzzing-modules.patch and registered in the PLUGINS
# list, but without a seed corpus directory no vlc-demux-dec-libfuzzer-mpgv binary
# is produced. This directly exercises modules/demux/mpeg/mpgv.c and the MPEG video
# packetizer (modules/packetizer/mpegvideo.c).
mkdir -p fuzz-corpus/seeds/mpgv
python3 -c "
# Minimal MPEG-1 video elementary stream seed.
# The sequence_header_code (0x000001B3) passes CheckMPEGStartCode in mpgv.c:
#   0xB3 is not in {0xB0, 0xB1, 0xB6} and 0xB3 <= 0xB9, so VLC_SUCCESS is returned.
# The demuxer opens without force and the Demux loop feeds data to the mpegvideo
# packetizer, exercising parsing logic for MPEG-I/II video bitstreams.
#
# Sequence header structure (ISO/IEC 11172-2 / ISO/IEC 13818-2):
#   start code (4B) | width(12b)/height(12b) | aspect(4b)/framerate(4b) |
#   bitrate(18b)/marker(1b)/vbv_size(10b)/constrained(1b)/load_flags(2b)
seed = bytes([
    # Sequence header: 352x240, 1:1 aspect, 29.97fps, VBR, vbv=0
    0x00, 0x00, 0x01, 0xB3,  # sequence_header_code
    0x16, 0x00, 0xF0,        # width=352(12b)|height=240(12b): 0001 0110 0000 | 0000 1111 0000
    0x15,                    # aspect=1(4b)|framerate=5(4b) = 0001 0101
    0xFF, 0xFF, 0xE0, 0x00,  # bitrate(18b)=0x3FFFF(VBR) marker=1 vbv(10b)=0 flags=0
    # Group of Pictures header: closed GOP, 00:00:00:00
    0x00, 0x00, 0x01, 0xB8,  # group_start_code
    0x00, 0x00, 0x01,        # time_code(25b)=0 closed_gop=0 broken_link=0
    # Picture header: temporal_ref=0, I-frame, no extra vbv_delay
    0x00, 0x00, 0x01, 0x00,  # picture_start_code
    0x00, 0x10, 0xFF, 0xFF,  # temporal_ref(10b)=0 picture_type(3b)=0x1(I) vbv_delay(16b)=0xFFFF
    # Slice: slice_vertical_position=1, quantiser_scale=1
    0x00, 0x00, 0x01, 0x01,  # slice_start_code (row 1)
    0x22, 0x00, 0x00,        # quantiser_scale=1, intra_slice=0, slice_data
])
open('fuzz-corpus/seeds/mpgv/minimal.mpgv', 'wb').write(seed)
print('Created mpgv seed: {} bytes'.format(len(seed)))
"

# MPEG video start-code dictionary for the mpgv fuzzer.
# These tokens help libFuzzer reach specific parsing branches in mpgv.c,
# mpegvideo packetizer, and the MPEG-4 IOD parser (mpeg4_iod.c via TS).
cat > fuzz-corpus/dictionaries/mpgv.dict << 'DICT_EOF'
# MPEG-1/2 video start codes (ISO/IEC 11172-2 / ISO/IEC 13818-2)
# libFuzzer dictionary format: one token per line, inline comments not allowed.
"\x00\x00\x01\xB3"
"\x00\x00\x01\xB7"
"\x00\x00\x01\xB8"
"\x00\x00\x01\x00"
"\x00\x00\x01\xB5"
"\x00\x00\x01\xB2"
"\x00\x00\x01\x01"
"\x00\x00\x01\xAF"
"\x00\x00\x01"
DICT_EOF

# Replace the existing TS seeds (which are all null-packets only and do not
# exercise any PAT/PMT/PES parsing) with proper structured TS streams.
# generate_ts_seeds.py builds 12 minimal TS files that each contain a valid
# PAT + PMT + at least one PES packet, directly exercising ts_psi.c, ts_pes.c,
# ts_pid.c, ts_streams.c, ts_decoders.c, ts_si.c, ts_scte.c in
# modules/demux/mpeg/.
python3 $SRC/generate_ts_seeds.py fuzz-corpus/seeds/ts

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

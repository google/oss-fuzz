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

# Use OSS-Fuzz environment rather than hardcoded setup.
sed -i 's/-fsanitize-coverage=trace-pc-guard//g' ./configure.ac
sed -i 's/-fsanitize-coverage=trace-cmp//g' ./configure.ac
sed -i 's/-fsanitize-coverage=trace-pc//g' ./configure.ac
sed -i 's/-lFuzzer//g'  ./configure.ac

# In order to build statically we avoid libxml and ogg plugins.
sed -i 's/..\/..\/lib\/libvlc_internal.h/lib\/libvlc_internal.h/g' ./test/src/input/decoder.c
sed -i 's/..\/modules\/libxml_plugin.la//g' ./test/Makefile.am
sed -i 's/..\/modules\/libogg_plugin.la//g' ./test/Makefile.am
sed -i 's/f(misc_xml_xml)//g' ./test/src/input/demux-run.c
sed -i 's/f(demux_ogg)//g' ./test/src/input/demux-run.c

# Ensure that we compile with the correct link flags.
RULE="vlc_demux_libfuzzer_LDADD"
FUZZ_LDFLAGS="vlc_demux_libfuzzer_LDFLAGS=\${LIB_FUZZING_ENGINE}"
sed -i "s/${RULE}/${FUZZ_LDFLAGS}\n${RULE}/g" ./test/Makefile.am

RULE="vlc_demux_dec_libfuzzer_LDADD"
FUZZ_LDFLAGS="vlc_demux_dec_libfuzzer_LDFLAGS=\${LIB_FUZZING_ENGINE}"
sed -i "s/${RULE}/${FUZZ_LDFLAGS}\n${RULE}/g" ./test/Makefile.am

./bootstrap
./configure --disable-ogg --disable-oggspots --disable-libxml2 --disable-lua \
            --disable-shared \
            --enable-static \
            --enable-vlc=no \
            --disable-avcodec \
            --disable-swscale \
            --disable-a52 \
            --disable-xcb \
            --disable-alsa \
            --with-libfuzzer
make V=1 -j$(nproc)
cp ./test/vlc-demux-dec-libfuzzer $OUT/
cp ./test/vlc-demux-libfuzzer $OUT/

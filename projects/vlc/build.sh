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

make V=1 -j$(nproc) \
    .matroska \
    .ogg \
    .libxml2

cd ../../

# Resume instrumentation
export CFLAGS="${CFLAGS_SAVE}"
export CXXFLAGS="${CXXFLAGS_SAVE}"
unset AFL_NOOPT

# Use OSS-Fuzz environment rather than hardcoded setup.
sed -i 's/-fsanitize-coverage=trace-pc-guard//g' ./configure.ac
sed -i 's/-fsanitize-coverage=trace-cmp//g' ./configure.ac
sed -i 's/-fsanitize-coverage=trace-pc//g' ./configure.ac
sed -i 's/-lFuzzer//g'  ./configure.ac

# Use default -lc++
sed -i 's/-lstdc++ //g' ./configure.ac
sed -i 's/-lstdc++/$(NULL)/g' ./test/Makefile.am

sed -i 's/..\/..\/lib\/libvlc_internal.h/lib\/libvlc_internal.h/g' ./test/src/input/decoder.c

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
            --disable-avcodec \
            --disable-swscale \
            --disable-a52 \
            --disable-xcb \
            --disable-alsa \
            --with-libfuzzer
make V=1 -j$(nproc)
cp ./test/vlc-demux-dec-libfuzzer $OUT/

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

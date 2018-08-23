#!/bin/bash -eu
# Copyright 2018 Google Inc.
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

# Case-sensitive names of internal Firefox fuzzing targets. Edit to add more.
FUZZ_TARGETS=(
  SdpParser
  StunParser
  # Qcms # needn't be enabled; has its own project with more sanitizers/engines
)

# Firefox object (build) directory.
OBJDIR=$WORK/obj-fuzz

[[ $SANITIZER = "coverage" ]] && touch $OUT/empty && exit 0

# Firefox fuzzing build configuration.
cat << EOF > mozconfig
ac_add_options --disable-debug
ac_add_options --disable-elf-hack
ac_add_options --disable-jemalloc
ac_add_options --disable-crashreporter
ac_add_options --enable-fuzzing
ac_add_options --enable-optimize=-O1
ac_add_options --enable-debug-symbols=-gline-tables-only
ac_add_options --enable-address-sanitizer
mk_add_options MOZ_OBJDIR=${OBJDIR}
mk_add_options MOZ_MAKE_FLAGS=-j$(nproc)
EOF

if [[ $SANITIZER = "address" ]]
then
cat << EOF >> mozconfig
mk_add_options CFLAGS=
mk_add_options CXXFLAGS=
EOF
fi

# Remove existing cargo configs (if any). Otherwise, mach fails.
if [ -d "$HOME/.cargo" ]; then rm -rf $HOME/.cargo; fi

# Install dependencies.
export SHELL=/bin/bash
./mach bootstrap --no-interactive --application-choice browser

# Set environment for rustc.
source $HOME/.cargo/env

# Update internal libFuzzer.
(cd tools/fuzzing/libfuzzer && ./clone_libfuzzer.sh HEAD)

# Build! Takes about 15 minutes on a 32 vCPU instance.
./mach build
./mach gtest buildbutdontrun

# Packages Firefox only to immediately extract the archive. Some files are
# replaced with gtest-variants, which is required by the fuzzing interface.
# Weighs in shy of 1GB afterwards.
make -j$(nproc) -C $OBJDIR package
tar -xf $OBJDIR/dist/firefox*bz2 -C $OUT
mv $OBJDIR/toolkit/library/gtest/libxul.so $OUT/firefox
mv $OUT/firefox/dependentlibs.list $OUT/firefox/dependentlibs.list.gtest

# Get the absolute paths of the required libraries.
export LD_LIBRARY_PATH=${LD_LIBRARY_PATH:-}:$OUT/firefox
REQUIRED_LIBRARIES=($(ldd $OUT/firefox/libxul.so | gawk '/=> [/]/ {print $3}'))
REQUIRED_LIBRARIES=(${REQUIRED_LIBRARIES[@]##$OUT/*})

mkdir $WORK/apt
chown _apt $WORK/apt # suppress warning message on each file
cd $WORK/apt

# Find and download packages which have the required files, ignoring some.
# Note that apt-file is very slow, hence parallel is used.
# Takes only 1-2 minutes on a 32 vCPU instance.
PACKAGES=($(parallel apt-file search -lFN "{}" ::: ${REQUIRED_LIBRARIES[@]}))
PACKAGES=(${PACKAGES[@]##libc6*})
PACKAGES=(${PACKAGES[@]##libgcc*})
PACKAGES=(${PACKAGES[@]##libstdc++*})
apt-get -q download ${PACKAGES[@]}

mkdir $WORK/deb
# Extract downloaded packages.
find $WORK/apt -type f -exec dpkg-deb --extract "{}" $WORK/deb \;

mkdir $OUT/lib
# Move required libraries. Less than 50MB total.
for REQUIRED_LIBRARY in ${REQUIRED_LIBRARIES[@]}
do
  find $WORK/deb \
    -xtype f -name "${REQUIRED_LIBRARY##*/}" -exec cp -uL "{}" $OUT/lib \;
done

# Build a wrapper binary for each target to set environment variables.
for FUZZ_TARGET in ${FUZZ_TARGETS[@]}
do
  $CC $CFLAGS -O0 \
    -DFUZZ_TARGET=$FUZZ_TARGET \
    $SRC/target.c -o $OUT/$FUZZ_TARGET
done

cd $SRC/mozilla-central

# SdpParser
find media/webrtc/trunk/webrtc/test/fuzzers/corpora/sdp-corpus \
  -type f -exec zip -qju $OUT/SdpParser_seed_corpus.zip "{}" \;
cp media/webrtc/trunk/webrtc/test/fuzzers/corpora/sdp.tokens \
  $OUT/SdpParser.dict

# StunParser
find media/webrtc/trunk/webrtc/test/fuzzers/corpora/stun-corpus \
  -type f -exec zip -qju $OUT/StunParser_seed_corpus.zip "{}" \;
cp media/webrtc/trunk/webrtc/test/fuzzers/corpora/stun.tokens \
  $OUT/StunParser.dict

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

[[ $SANITIZER = "coverage" ]] && touch $OUT/exit && exit 0

# Case-sensitive names of internal Firefox fuzzing targets. Edit to add more.
FUZZ_TARGETS=(
  SdpParser
  StunParser
  ContentParentIPC
  ContentSecurityPolicyParser
  # Qcms # needn't be enabled; has its own project with more sanitizers/engines
)

# Firefox object (build) directory and configuration file.
export MOZ_OBJDIR=$WORK/obj-fuzz
export MOZCONFIG=$SRC/mozconfig.$SANITIZER

# Install dependencies. Note that bootstrap installs cargo, which must be added
# to PATH via source. In a successive run (for a different sanitizer), the
# cargo installation carries over, but bootstrap fails if cargo is not in PATH.
export SHELL=/bin/bash
[[ -f "$HOME/.cargo/env" ]] && source $HOME/.cargo/env
./mach bootstrap --no-interactive --application-choice browser
source $HOME/.cargo/env

# Update internal libFuzzer.
(cd tools/fuzzing/libfuzzer && ./clone_libfuzzer.sh HEAD)

# Build! Takes about 15 minutes on a 32 vCPU instance.
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

# ContentParentIPC
cp $SRC/fuzzdata/settings/ipc/libfuzzer.content.blacklist.txt $OUT/firefox

# ContentSecurityPolicyParser
cp dom/security/fuzztest/csp_fuzzer.dict $OUT/ContentSecurityPolicyParser.dict

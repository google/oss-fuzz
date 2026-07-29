#!/bin/bash -eu
# Copyright 2026 Google LLC
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
#
# OSS-Fuzz build script for tcpreplay.
#
# OSS-Fuzz supplies the compiler, the sanitizer flags and $LIB_FUZZING_ENGINE,
# so this deliberately does not choose any of them - it configures the tree the
# normal way and links the targets against whatever the engine is. That keeps
# the same harnesses working under libFuzzer, AFL++ and Honggfuzz without
# per-engine variants.
#
# Referenced from an oss-fuzz/projects/tcpreplay/Dockerfile that clones this
# repo and runs this script. Kept in-tree so it stays in step with the targets.

cd "$SRC/tcpreplay"

./autogen.sh
# --disable-local-libopts: the tearoff is CLI plumbing, not attack surface, and
# building it wastes fuzzing budget.
./configure --disable-local-libopts
make -j"$(nproc)"

# libdnet is optional, and fragroute is the only target that needs it - Debian/
# Ubuntu (including this image) package it as libdumbnet, not libdnet, so the
# link flag has to come from wherever ./configure already worked that out
# rather than being guessed here. test/fuzz/Makefile has it after configure
# runs above, whether or not fragroute itself is actually available.
FRAGROUTE_LIB=""
FRAGROUTE_LIBNET=""
if [ -f src/fragroute/libfragroute.a ]; then
    FRAGROUTE_LIB="src/fragroute/libfragroute.a"
    FRAGROUTE_LIBNET=$(sed -n 's/^LDNETLIB = //p' test/fuzz/Makefile)
fi

for target in fuzz_services fuzz_pcap fuzz_fragroute; do
    [ -f "test/fuzz/${target}.c" ] || continue
    if [ "$target" = "fuzz_fragroute" ] && [ -z "$FRAGROUTE_LIB" ]; then
        continue
    fi

    libs="src/common/libcommon.a -lpcap"
    if [ "$target" = "fuzz_fragroute" ]; then
        libs="$FRAGROUTE_LIB $libs $FRAGROUTE_LIBNET"
    fi

    $CC $CFLAGS -DHAVE_CONFIG_H -I. -Isrc -Itest/fuzz -c "test/fuzz/${target}.c" -o "$WORK/${target}.o"
    $CXX $CXXFLAGS "$WORK/${target}.o" $LIB_FUZZING_ENGINE $libs -o "$OUT/${target}"

    # ship the seed corpus so the engine starts from valid inputs
    name="${target#fuzz_}"
    if [ -d "test/fuzz/corpus/$name" ]; then
        zip -j "$OUT/${target}_seed_corpus.zip" "test/fuzz/corpus/$name"/* > /dev/null
    fi
done

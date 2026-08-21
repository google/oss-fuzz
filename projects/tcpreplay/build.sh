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

# The Dockerfile installs libpcap-dev so this build (and tcpreplay's own
# normal build) can find pcap.h/link against something - but the fuzz targets
# link against a *separately built* libpcap.a below, not that system package.
#
# Debian/Ubuntu's libpcap is built with D-Bus, Bluetooth and USB sniffing
# support enabled, each pulling in its own shared library (libdbus-1,
# libsystemd, and libsystemd's own dependency on libcap in turn). All of that
# is dynamically linked into libpcap.so, so the *build* step here links fine
# - the base-builder image has every one of those .so files. OSS-Fuzz's
# separate runner image, where the built binaries actually execute, does not:
# it installs only libcap2 (see infra/base-images/base-runner/install_deps.sh
# upstream), not libdbus-1 or libsystemd. The result was every target dying
# at startup with "error while loading shared libraries: libpcap.so.0.8:
# cannot open shared object file" - a build that reported success but
# produced nothing that could actually run.
#
# Linking the *system* libpcap.a statically doesn't fix this - it just moves
# the missing .so from libpcap itself to whatever libpcap.a still pulls in
# (dbus, systemd, and transitively libcap's cap_* symbols, none of which are
# needed for reading pcap files). None of that is needed to fuzz the pcap
# read path, so it's built out entirely: a self-contained libpcap.a with the
# capture backends that need those disabled, leaving nothing for a fuzz
# target to depend on beyond libc/libstdc++/libm - which the runner image, or
# any Linux system, always has.
cd "$SRC/libpcap"
mkdir -p build
cd build
cmake -DBUILD_SHARED_LIBS=OFF -DDISABLE_DBUS=ON -DDISABLE_BLUETOOTH=ON \
      -DDISABLE_LINUX_USBMON=ON -DDISABLE_RDMA=ON ..
make -j"$(nproc)" pcap_static
LIBPCAP_A="$SRC/libpcap/build/libpcap.a"
cd "$SRC/tcpreplay"

# libdnet is optional, and fragroute is the only target that needs it - Debian/
# Ubuntu (including this image) package it as libdumbnet, not libdnet, so the
# link flag has to come from wherever ./configure already worked that out
# rather than being guessed here. test/fuzz/Makefile has it after configure
# runs above, whether or not fragroute itself is actually available. Statically
# linked for the same reason as libpcap above; libdumbnet has no equivalent
# transitive dependency problem, so the system copy is fine to use as-is.
FRAGROUTE_LIB=""
FRAGROUTE_LIBNET=""
if [ -f src/fragroute/libfragroute.a ]; then
    FRAGROUTE_LIB="src/fragroute/libfragroute.a"
    FRAGROUTE_LIBNET="-Wl,-Bstatic $(sed -n 's/^LDNETLIB = //p' test/fuzz/Makefile) -Wl,-Bdynamic"
fi

for target in fuzz_services fuzz_pcap fuzz_fragroute; do
    [ -f "test/fuzz/${target}.c" ] || continue
    if [ "$target" = "fuzz_fragroute" ] && [ -z "$FRAGROUTE_LIB" ]; then
        continue
    fi

    # Link order matters for static archives: they only resolve symbols for
    # things listed *after* them, so each library has to come before whatever
    # it depends on - libfragroute needs libcommon and libdumbnet, libcommon
    # needs libpcap.
    libs="src/common/libcommon.a $LIBPCAP_A"
    if [ "$target" = "fuzz_fragroute" ]; then
        libs="$FRAGROUTE_LIB src/common/libcommon.a $LIBPCAP_A $FRAGROUTE_LIBNET"
    fi

    $CC $CFLAGS -DHAVE_CONFIG_H -I. -Isrc -Itest/fuzz -c "test/fuzz/${target}.c" -o "$WORK/${target}.o"
    $CXX $CXXFLAGS "$WORK/${target}.o" $LIB_FUZZING_ENGINE $libs -o "$OUT/${target}"

    # ship the seed corpus so the engine starts from valid inputs
    name="${target#fuzz_}"
    if [ -d "test/fuzz/corpus/$name" ]; then
        zip -j "$OUT/${target}_seed_corpus.zip" "test/fuzz/corpus/$name"/* > /dev/null
    fi
done

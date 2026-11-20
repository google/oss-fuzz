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

cd $SRC/phosphor-networkd

# Disable C99 extension warning in C++ (triggered by SD_BUS_ERROR_NULL in systemd headers)
export CXXFLAGS="$CXXFLAGS -Wno-c99-extensions"
export LDFLAGS="$CXXFLAGS"

# Clean git state and download subprojects (excluding unused googletest)
git checkout -- . || true
rm -f subprojects/googletest.wrap
rm -rf subprojects/googletest || true
for sub in sdbusplus stdplus phosphor-logging phosphor-dbus-interfaces; do
    if [ -d "subprojects/$sub" ]; then git -C "subprojects/$sub" checkout -- . || true; fi
done
meson subprojects download || true

# Add fuzzing options and subdirectory to meson
if ! grep -q "subdir('fuzzing')" meson.build; then
    cat << 'EOF' >> meson.build
if get_option('fuzzing').allowed()
    subdir('fuzzing')
endif
EOF
fi

if ! grep -q "'fuzzing'" meson.options; then
    cat << 'EOF' >> meson.options
option('fuzzing', type: 'feature', value: 'disabled', description: 'Build fuzz targets')
option('fuzzing_engine', type: 'string', value: '-fsanitize=fuzzer', description: 'Fuzzing engine link arguments')
EOF
fi

# Copy fuzzer files into the source tree
mkdir -p fuzzing
cp $SRC/*_fuzzer.cpp fuzzing/
cp $SRC/fuzzing_meson.build fuzzing/meson.build

# Configure the project with Meson
rm -rf builddir
meson setup builddir \
    -Dfuzzing=enabled \
    -Dfuzzing_engine="$LIB_FUZZING_ENGINE" \
    -Dtests=disabled \
    -Dhyp-nw-config=false \
    -Dwerror=false \
    -Ddefault_library=static \
    --buildtype=debugoptimized

# Patch subprojects for libc++ compatibility
if [ -f subprojects/sdbusplus/include/sdbusplus/event.hpp ]; then
    grep -q '#include <unistd.h>' subprojects/sdbusplus/include/sdbusplus/event.hpp || \
        sed -i '1s/^/#include <unistd.h>\n/' subprojects/sdbusplus/include/sdbusplus/event.hpp
fi
if [ -d subprojects/stdplus ]; then
    git -C subprojects/stdplus apply $SRC/stdplus.patch || true
fi
if [ -d subprojects/stdexec ]; then
    find subprojects/stdexec -name '__utility.hpp' -exec sed -i '1i#include <new>' {} + || true
fi

# Build the fuzzers
ninja -C builddir \
    fuzzing/config_parser_fuzzer \
    fuzzing/rtnetlink_fuzzer \
    fuzzing/util_fuzzer

# Copy fuzzers and dictionary to $OUT
cp builddir/fuzzing/config_parser_fuzzer $OUT/
cp builddir/fuzzing/rtnetlink_fuzzer $OUT/
cp builddir/fuzzing/util_fuzzer $OUT/
cp $SRC/config_parser_fuzzer.dict $OUT/

# Package seed corpora
zip -j $OUT/config_parser_fuzzer_seed_corpus.zip $SRC/corpus/config_parser/*
zip -j $OUT/rtnetlink_fuzzer_seed_corpus.zip $SRC/corpus/rtnetlink/*
zip -j $OUT/util_fuzzer_seed_corpus.zip $SRC/corpus/util/*

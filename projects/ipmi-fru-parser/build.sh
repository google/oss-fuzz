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

# Pre-clone all git wrap subprojects manually so we can patch them before Meson setup runs
for wrap in subprojects/*.wrap; do
    if [ -f "$wrap" ]; then
        name=$(basename "$wrap" .wrap)
        url=$(grep -E '^url\s*=' "$wrap" | cut -d'=' -f2 | tr -d ' ')
        if [ -n "$url" ] && [ ! -d "subprojects/$name" ]; then
            git clone --depth 1 "$url" "subprojects/$name" || true
        fi
    fi
done

# Fix meson_version requirements in all subprojects
find subprojects/ -name "meson.build" -exec sed -i "s/meson_version: '>=1.8.99'/meson_version: '>=1.1.0'/g" {} +

# Patch sdbusplus to include <unistd.h> across all header and source files for close()
if [ -d subprojects/sdbusplus ]; then
    find subprojects/sdbusplus -type f \( -name "*.hpp" -o -name "*.cpp" \) -exec sed -i '1s/^/#include <unistd.h>\n/' {} +
fi

# Patch sdbusplus event.cpp for sd_event_add_time_relative fallback on older systemd
if [ -f subprojects/sdbusplus/src/event.cpp ]; then
    sed -i '1s/^/#include <systemd\/sd-event.h>\n#ifndef sd_event_add_time_relative\n#define sd_event_add_time_relative(event, timer, clock, usec, accuracy, callback, userdata) ({ uint64_t _now = 0; sd_event_now(event, clock, \&_now); sd_event_add_time(event, timer, clock, _now + (usec), accuracy, callback, userdata); })\n#endif\n/' subprojects/sdbusplus/src/event.cpp
fi

# Disable transport and serialbridge in phosphor-host-ipmid
if [ -f subprojects/phosphor-host-ipmid/meson.build ]; then
    sed -i "s/subdir('transport')/# subdir('transport')/g" subprojects/phosphor-host-ipmid/meson.build
fi
find subprojects/ -path "*/transport/serialbridge/meson.build" -exec sh -c 'echo "" > "$1"' _ {} +
find subprojects/ -path "*/transport/meson.build" -exec sh -c 'echo "" > "$1"' _ {} +

# Install sdbus++ from subproject tools if present
if [ -d subprojects/sdbusplus/tools ]; then
    pip3 install subprojects/sdbusplus/tools || true
fi

# Configure Meson with static libraries and pass CXXFLAGS to ensure ABI compatibility (libc++)
meson setup build \
    --default-library=static \
    -Dwerror=false \
    -Dcpp_args="$CXXFLAGS" \
    -Dcpp_link_args="$CXXFLAGS"

# Build libwritefrudata.a and sdbusplus
ninja -C build libwritefrudata.a subprojects/sdbusplus/libsdbusplus.a

# Gather all compiled object files (excluding main/test objects) into a single static archive
ALL_OBJS=$(find build -name "*.o" ! -name "*argument*.o" ! -name "*main*.o" ! -name "*test*.o")
ar rcs build/liball_objs.a $ALL_OBJS

# Generate seed corpus
python3 $SRC/generate_seeds.py $OUT/fuzz_fru_parser_seed_corpus.zip

# Specific phosphor-logging sources needed for lg2 logging
LOG_SRCS="subprojects/phosphor-logging/lib/lg2_logger.cpp subprojects/phosphor-logging/lib/sdjournal.cpp"

# Find all static libraries generated in build/
ALL_LIBS=$(find build -type f -name "*.a" | tr '\n' ' ')

# Dynamically gather include paths from subprojects and build directory
INC_PATHS=$(find subprojects build -type d \( -name "include" -o -name "single_include" \) -exec echo -I/src/ipmi-fru-parser/{} \;)

# Compile fuzz harness
$CXX $CXXFLAGS -std=c++23 \
    -I$SRC/ipmi-fru-parser \
    -I$SRC/ipmi-fru-parser/build \
    $INC_PATHS \
    $SRC/fuzz_fru_parser.cpp \
    $LOG_SRCS \
    -o $OUT/fuzz_fru_parser \
    $LIB_FUZZING_ENGINE \
    -Wl,--start-group $ALL_LIBS -Wl,--end-group \
    -lsystemd

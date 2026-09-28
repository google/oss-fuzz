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

INCLUDES="-I$SRC/dbus-sensors/src -I$SRC/dbus-sensors/include -include $SRC/boost_compat.h $(pkg-config --cflags sdbusplus phosphor-logging)"
DEFINES="-D_GNU_SOURCE -DBOOST_ALLOW_DEPRECATED_HEADERS -DBOOST_ASIO_DISABLE_THREADS"

# Create header for dbus-sensor_config.h
cat << 'EOF' > $SRC/dbus-sensors/src/dbus-sensor_config.h
#pragma once
constexpr const int validateUnsecureFeature = 0;
constexpr const int insecureSensorOverride = 0;
EOF

# Compile static object files for utils, thresholds, and devicemgmt
$CXX $CXXFLAGS $INCLUDES $DEFINES -std=c++23 -c $SRC/dbus-sensors/src/Utils.cpp -o $WORK/Utils.o
$CXX $CXXFLAGS $INCLUDES $DEFINES -std=c++23 -c $SRC/dbus-sensors/src/Thresholds.cpp -o $WORK/Thresholds.o
$CXX $CXXFLAGS $INCLUDES $DEFINES -std=c++23 -c $SRC/dbus-sensors/src/SensorPaths.cpp -o $WORK/SensorPaths.o
$CXX $CXXFLAGS $INCLUDES $DEFINES -std=c++23 -c $SRC/dbus-sensors/src/DeviceMgmt.cpp -o $WORK/DeviceMgmt.o
$CXX $CXXFLAGS $INCLUDES $DEFINES -std=c++23 -c $SRC/dbus-sensors/src/FileHandle.cpp -o $WORK/FileHandle.o

# Build fuzzer
$CXX $CXXFLAGS $DEFINES $INCLUDES -std=c++23 $SRC/utils_fuzzer.cpp \
    /work/Utils.o /work/Thresholds.o /work/SensorPaths.o /work/DeviceMgmt.o /work/FileHandle.o \
    $LIB_FUZZING_ENGINE \
    -L/usr/local/lib/x86_64-linux-gnu -lsdbusplus -lsystemd \
    -L/usr/local/lib -lphosphor_logging -lsystemd \
    /usr/lib/x86_64-linux-gnu/libssl.a /usr/lib/x86_64-linux-gnu/libcrypto.a \
    -o $OUT/utils_fuzzer

#!/bin/bash -eu
# Copyright 2023 Google LLC
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

# mosquitto's CMake picks up the shared libargon2, which is not available in
# the OSS-Fuzz runtime image, so all fuzz targets fail to start with
# "error while loading shared libraries: libargon2.so.1". Point find_library
# at the static library instead (argon2 is not actually used by the fuzzers,
# but it is linked transitively through libmosquitto_common).
ARGON2_STATIC_DIR="${WORK}/argon2-static"
ARGON2_STATIC_LIB="$(pkg-config --variable=libdir libargon2)/libargon2.a"
test -f "${ARGON2_STATIC_LIB}"
mkdir -p "${ARGON2_STATIC_DIR}/lib"
ln -sf "${ARGON2_STATIC_LIB}" "${ARGON2_STATIC_DIR}/lib/libargon2.a"
export CMAKE_PREFIX_PATH="${ARGON2_STATIC_DIR}${CMAKE_PREFIX_PATH:+:${CMAKE_PREFIX_PATH}}"

# Run build script from the mosquitto repo
./fuzzing/scripts/oss-fuzz-build.sh

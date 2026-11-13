#!/bin/bash
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

# OSS-Fuzz compatible build script for OpenLDAP fuzzing harnesses
#
# This script builds OpenLDAP libraries and fuzzing harnesses compatible with
# LibFuzzer and OSS-Fuzz infrastructure.
set -e  # Exit on error
set -x  # Print commands (helpful for debugging)

# Set defaults for local testing
export CC=${CC:-clang}
export CXX=${CXX:-clang++}
export CFLAGS=${CFLAGS:--fsanitize=address,fuzzer-no-link -g}
export CXXFLAGS=${CXXFLAGS:--fsanitize=address,fuzzer-no-link -g}
export LIB_FUZZING_ENGINE=${LIB_FUZZING_ENGINE:--fsanitize=fuzzer}
export OUT=${OUT:-/out}
export SRC=${SRC:-/src}

# OpenLDAP source directory
OPENLDAP_SRC="${SRC}/openldap"
cd "${OPENLDAP_SRC}"

# Create output directory if it doesn't exist
mkdir -p "${OUT}"

# Configure OpenLDAP
# We only need the client libraries (libldap, liblber) for fuzzing the public API.
# Disable server components (slapd) to reduce build time and dependencies.
#
# Key configure options:
#   --disable-slapd           : Don't build the LDAP server
#   --disable-backends        : Don't build any backend databases
#   --disable-overlays        : Don't build overlays
#   --disable-syslog          : Reduce external dependencies
#   --disable-shared          : Prefer static linking for fuzzing
#   --enable-static           : Build static libraries
#   --without-cyrus-sasl      : Disable SASL to reduce dependencies
#   --without-fetch           : Disable fetch support
#   --without-threads         : Disable threading (simpler for fuzzing)
#   --disable-slapi           : Disable server plugin API


# Clean any previous configuration
make distclean 2>/dev/null || true

./configure \
    --disable-slapd \
    --disable-backends \
    --disable-overlays \
    --disable-syslog \
    --disable-shared \
    --enable-static \
    --without-cyrus-sasl \
    --without-fetch \
    --without-threads \
    --without-tls \
    --disable-slapi \
    --prefix="${OPENLDAP_SRC}/install"


# Build dependencies first
make -j$(nproc) -C include
make -j$(nproc) -C libraries


# Common include paths
INCLUDES="-I${OPENLDAP_SRC}/include -I${OPENLDAP_SRC}/libraries/libldap -I${OPENLDAP_SRC}/libraries/liblber"

# Library paths (prefer static archives)
LDAP_LIBS="${OPENLDAP_SRC}/libraries/libldap/.libs/libldap.a"
LBER_LIBS="${OPENLDAP_SRC}/libraries/liblber/.libs/liblber.a"
LUTIL_LIBS="${OPENLDAP_SRC}/libraries/liblutil/liblutil.a"
REWRITE_LIBS="${OPENLDAP_SRC}/libraries/librewrite/librewrite.a"

# Link order matters: libldap depends on liblber and liblutil
STATIC_LIBS="${LDAP_LIBS} ${LBER_LIBS} ${LUTIL_LIBS} ${REWRITE_LIBS}"

# System libraries that OpenLDAP may depend on
SYSTEM_LIBS="-lresolv"

# Find all fuzzer harnesses in fuzz/ directory
for fuzzer_source in "${SRC}"/fuzz_*.cpp; do
    if [ ! -f "$fuzzer_source" ]; then
        echo "[!] No fuzzer harnesses found in fuzz/ directory"
        exit 1
    fi

    fuzzer_name=$(basename "$fuzzer_source" .cpp)
    echo "[*] Building ${fuzzer_name}..."

    # Compile fuzzer harness
    # Link order: fuzzer source -> static libs -> system libs -> fuzzing engine
    ${CXX} ${CXXFLAGS} ${INCLUDES} \
        "$fuzzer_source" \
        ${STATIC_LIBS} \
        ${SYSTEM_LIBS} \
        ${LIB_FUZZING_ENGINE} \
        -o "${OUT}/${fuzzer_name}"

    echo "[+] Built: ${OUT}/${fuzzer_name}"
done



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

cd $SRC/nmap

# Build nmap's libraries (we need nbase and libnetutil)
# Configure with minimal features to reduce build complexity
./configure \
    --without-zenmap \
    --without-ncat \
    --without-ndiff \
    --without-nping \
    --without-openssl \
    --without-libssh2 \
    --with-pcap=null \
    CC="$CC" CXX="$CXX" CFLAGS="$CFLAGS" CXXFLAGS="$CXXFLAGS" \
    || true

# Build nbase first
cd $SRC/nmap/nbase
make -j$(nproc) || true

cd $SRC/nmap

# Compile key source files individually for fuzzing
NMAP_INCLUDES="-I. -Inbase -Ilibnetutil -Ilibpcap -Ilibpcre"

# Build nbase objects
NBASE_OBJS=""
for f in nbase/nbase_str.o nbase/nbase_misc.o nbase/nbase_memalloc.o; do
    if [ -f "$f" ]; then
        NBASE_OBJS="$NBASE_OBJS $f"
    fi
done

# Compile service_scan parsing components
$CXX $CXXFLAGS $NMAP_INCLUDES -c charpool.cc -o charpool.o || true
$CXX $CXXFLAGS $NMAP_INCLUDES -c utils.cc -o utils.o || true
$CXX $CXXFLAGS $NMAP_INCLUDES -c string_pool.cc -o string_pool.o || true

# === fuzz_target_parse: Target specification parsing ===
# This fuzzes nmap's target parsing (CIDR, IP ranges, hostnames)
$CXX $CXXFLAGS $NMAP_INCLUDES \
    -c $SRC/fuzz_target_parse.cc -o fuzz_target_parse.o

$CXX $CXXFLAGS $LIB_FUZZING_ENGINE \
    fuzz_target_parse.o \
    $NBASE_OBJS \
    -o $OUT/fuzz_target_parse || \
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE \
    fuzz_target_parse.o \
    -o $OUT/fuzz_target_parse

cp $SRC/fuzz_target_parse.dict $OUT/ || true

# === fuzz_service_probe: Service probe matching ===
$CXX $CXXFLAGS $NMAP_INCLUDES \
    -c $SRC/fuzz_service_probe.cc -o fuzz_service_probe.o

$CXX $CXXFLAGS $LIB_FUZZING_ENGINE \
    fuzz_service_probe.o \
    $NBASE_OBJS \
    -o $OUT/fuzz_service_probe || \
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE \
    fuzz_service_probe.o \
    -o $OUT/fuzz_service_probe

cp $SRC/fuzz_service_probe.dict $OUT/ || true

# === fuzz_xml_output: XML parsing ===
$CXX $CXXFLAGS $NMAP_INCLUDES \
    -c $SRC/fuzz_xml_output.cc -o fuzz_xml_output.o

$CXX $CXXFLAGS $LIB_FUZZING_ENGINE \
    fuzz_xml_output.o \
    $NBASE_OBJS \
    -o $OUT/fuzz_xml_output || \
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE \
    fuzz_xml_output.o \
    -o $OUT/fuzz_xml_output

cp $SRC/fuzz_xml_output.dict $OUT/ || true

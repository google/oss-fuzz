#!/bin/bash -eu
# Copyright 2025 Google LLC
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

set -o pipefail

export CXXFLAGS="${CXXFLAGS} -std=c++20"
export CFLAGS="${CFLAGS}"

# Build cpp-libp2p with minimal options (no tests/examples)
mkdir -p $SRC/cpp-libp2p/build
cd $SRC/cpp-libp2p/build

cmake -G "Ninja" \
  -DCMAKE_BUILD_TYPE=Release \
  -DTESTING=OFF \
  -DEXAMPLES=OFF \
  -DCMAKE_CXX_FLAGS="${CXXFLAGS}" \
  -DCMAKE_C_FLAGS="${CFLAGS}" \
  ..

ninja -j"$(nproc)"

cd $SRC

# Helper to locate built static libraries
find_lib() {
  local name="$1"; shift || true
  local found
  found=$(find "$SRC/cpp-libp2p/build" -name "lib${name}.a" -print -quit)
  if [ -z "$found" ]; then
    echo "Failed to find lib${name}.a" >&2
    exit 1
  fi
  echo "$found"
}

INCLUDE_FLAGS=(
  -I"$SRC/cpp-libp2p/include"
)

# Build fuzzers

# 1) Multibase decode fuzzing
$CXX ${CXXFLAGS} \
  multibase_decode_fuzzer.cc \
  "${INCLUDE_FLAGS[@]}" \
  $(find_lib p2p_multibase_codec) \
  $LIB_FUZZING_ENGINE -lpthread -o $OUT/multibase_decode_fuzzer

# 2) Multihash parse fuzzing
$CXX ${CXXFLAGS} \
  multihash_parse_fuzzer.cc \
  "${INCLUDE_FLAGS[@]}" \
  $(find_lib p2p_multihash) \
  $(find_lib p2p_varint_prefix_reader) \
  $LIB_FUZZING_ENGINE -lpthread -o $OUT/multihash_parse_fuzzer

# 3) Multiaddress parse fuzzing
$CXX ${CXXFLAGS} \
  multiaddress_parse_fuzzer.cc \
  "${INCLUDE_FLAGS[@]}" \
  $(find_lib p2p_multiaddress) \
  $(find_lib p2p_converters) \
  $(find_lib p2p_uvarint) \
  $(find_lib p2p_byteutil) \
  $(find_lib p2p_multibase_codec) \
  $LIB_FUZZING_ENGINE -lpthread -o $OUT/multiaddress_parse_fuzzer

# 4) Multiselect parser fuzzing (backup)
$CXX ${CXXFLAGS} \
  multiselect_parser_fuzzer.cc \
  "${INCLUDE_FLAGS[@]}" \
  $(find_lib p2p_multiselect) \
  $(find_lib p2p_read_buffer) \
  $(find_lib p2p_varint_prefix_reader) \
  $(find_lib p2p_logger) \
  $(find "$SRC/cpp-libp2p/build" -name 'libsoralog*.a' -print) \
  $(find "$SRC/cpp-libp2p/build" -name 'libyaml-cpp*.a' -print | head -n 1) \
  $(find "$SRC/cpp-libp2p/build" -name 'libfmt*.a' -print | head -n 1) \
  $LIB_FUZZING_ENGINE -lpthread -o $OUT/multiselect_parser_fuzzer

# 5) BigEndian MessageReadWriter write UAF (backup)
$CXX ${CXXFLAGS} \
  message_read_writer_bigendian_write_uaf_fuzzer.cc \
  "${INCLUDE_FLAGS[@]}" \
  $(find_lib p2p_message_read_writer) \
  $(find_lib p2p_message_read_writer_error) \
  $(find_lib p2p_varint_reader) \
  $(find_lib p2p_uvarint) \
  $LIB_FUZZING_ENGINE -lpthread -o $OUT/message_read_writer_bigendian_write_uaf_fuzzer

# 6) BigEndian MessageReadWriter read length (backup)
$CXX ${CXXFLAGS} \
  message_read_writer_bigendian_read_len_fuzzer.cc \
  "${INCLUDE_FLAGS[@]}" \
  $(find_lib p2p_message_read_writer) \
  $(find_lib p2p_message_read_writer_error) \
  $(find_lib p2p_varint_reader) \
  $(find_lib p2p_uvarint) \
  $LIB_FUZZING_ENGINE -lpthread -o $OUT/message_read_writer_bigendian_read_len_fuzzer

# Seed corpora can be added later; current fuzzers start without seeds.

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

export ASAN_OPTIONS=detect_leaks=0

if [[ ! -z "${CXX:-}" ]]; then
  export CXX="${CXX//-lresolv/}"
fi

# Build and install the compiler...
# Disable other languages to save on compile time
./bootstrap.sh
# ... this forces go to be downloaded/installed, otherwise the configure script chokes when running go version
go version
./configure --enable-static --disable-shared --with-cpp=no --with-c_glib=no --with-python=no --with-py3=no --with-go=yes --with-rs=no --with-java=no --with-nodejs=no --with-dotnet=no --with-kotlin=no
make -j$(nproc)

pushd lib/go/test/fuzz

make gopathfuzz
compile_go_fuzzer . FuzzTutorial fuzz_tutorial
compile_go_fuzzer . FuzzParseBinary fuzz_parse_binary
compile_go_fuzzer . FuzzParseCompact fuzz_parse_compact
compile_go_fuzzer . FuzzParseJson fuzz_parse_json
compile_go_fuzzer . FuzzRoundtripBinary fuzz_roundtrip_binary
compile_go_fuzzer . FuzzRoundtripCompact fuzz_roundtrip_compact
compile_go_fuzzer . FuzzRoundtripJson fuzz_roundtrip_json

popd

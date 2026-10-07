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

# This script is useful for OSS-Fuzz infrastructure which is used to rebuild
# code from cached images. This is to support various ongoing efforts in
# OSS-Fuzz.

# List of targets disabled for oss-fuzz.                                        
declare -A disabled=()
# List of targets we want to fuzz in TLS and non-TLS mode.
declare -A tls_targets=([tls-client]=1 [tls-server]=1 [dtls-client]=1 [dtls-server]=1)
# Helper function that copies a fuzzer binary and its seed corpus.
copy_fuzzer()
{
    local fuzzer=$1
    local name=$2
    # Copy the binary.
    cp ../dist/Debug/bin/$fuzzer $OUT/$name
}

# Rebuild the library using most recent cache
cd $SRC/nss
ninja -C /src/nss/out/Debug -v                                                

# Copy dual mode targets in TLS mode.                                          
for name in "${!tls_targets[@]}"; do
    if [ -z "${disabled[$name]:-}" ]; then
        copy_fuzzer nssfuzz-$name $name
    fi
done

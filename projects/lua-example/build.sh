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

# Finish execution if libFuzzer is not used, because luzer
# is libFuzzer-based.
if [[ "$FUZZING_ENGINE" != libfuzzer ]]; then
  return
fi

# Install dependencies:
# 1. The libraries required for building luzer module.
# 2. PUC Rio Lua executable, required for running tests itself.
# 3. The Lua package manager.
apt install -y cmake liblua5.1-0 liblua5.1-0-dev lua5.1 luarocks

export OSS_FUZZ=1
# Install Lua libraries.
luarocks install --lua-version 5.1 --server=https://luarocks.org/dev --tree=lua_modules luzer

LUA_RUNTIME_NAME=lua

# Build fuzzers.
$SRC/compile_lua_fuzzer $LUA_RUNTIME_NAME fuzz_basic.lua

cp fuzz_basic.lua "$OUT/"
cp /usr/bin/lua5.1 "$OUT/$LUA_RUNTIME_NAME"
cp -R lua_modules "$OUT/"

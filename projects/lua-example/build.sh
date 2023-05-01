#!/bin/bash -eu
# Copyright 2023-2025 Google LLC
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

# Install dependencies.
apt install -y liblua5.1-0 liblua5.1-0-dev lua5.1 cmake luarocks \
               clang-18 libclang-rt-18-dev libc++-18-dev

# Install Lua dependencies.
# luarocks install --tree=lua_modules --server=https://luarocks.org/dev luzer
# TODO: A custom rockspec is used because custom branch is required,
# see https://github.com/ligurio/luzer/issues/63.
luarocks install --tree=lua_modules $SRC/luzer-scm-1.rockspec
zip -r lua_modules.zip lua_modules

LUA_RUNTIME_NAME=lua

# Build fuzzers.
$SRC/compile_lua_fuzzer lua-example $LUA_RUNTIME_NAME fuzz_basic.lua

cp fuzz_basic.lua "$OUT/"
cp /usr/bin/lua5.1 "$OUT/$LUA_RUNTIME_NAME"
cp lua_modules.zip "$OUT/"

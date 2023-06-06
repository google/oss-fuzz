#!/bin/bash -eux
# Copyright 2020 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# Copyright 2020 Google Inc.
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

# Environment: Zephyr has its own toolchain selection mechanism, and
# the oss-fuzz environment generates warnings and confuses things when
# building some of the (un-fuzzed) build-time tools that aren't quite
# clang-compatible.
export ZEPHYR_TOOLCHAIN_VARIANT=llvm
unset CC
unset CCC
unset CXX
unset CFLAGS
unset CXXFLAGS

BASE_CFG=(
-DCONFIG_ASSERT=y
-DCONFIG_SYS_HEAP_BIG_ONLY=y
-DCONFIG_ZEPHYR_NATIVE_DRIVERS=y
-DCONFIG_ARCH_POSIX_LIBFUZZER=y
-DCONFIG_ARCH_POSIX_FUZZ_TICKS=100
-DCONFIG_ASAN=y
)

cd $SRC/sof/sof

west build -p -b native_posix ./app -- "${BASE_CFG[@]}"
cp build/zephyr/zephyr.exe $OUT/sof-ipc3

west build -p -b native_posix ./app -- "${BASE_CFG[@]}" -DCONFIG_IPC_MAJOR_4=y
cp build/zephyr/zephyr.exe $OUT/sof-ipc4

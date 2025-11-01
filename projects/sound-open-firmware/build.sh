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

cd $SRC/sof_workspace

sof/scripts/fuzz.sh -b -s $SANITIZER -a $ARCHITECTURE -- -DEXTRA_CONF_FILE=stub_build_all_ipc3.conf -DEXTRA_CFLAGS="-fno-sanitize-recover=all"
cp build-fuzz/zephyr/zephyr.exe $OUT/sof-ipc3
zip $OUT/sof-ipc3.zip sof/tools/corpus/sof-ipc3/*

sof/scripts/fuzz.sh -b -s $SANITIZER -a $ARCHITECTURE -- -DEXTRA_CONF_FILE=stub_build_all_ipc4.conf -DEXTRA_CFLAGS="-fno-sanitize-recover=all"
cp build-fuzz/zephyr/zephyr.exe $OUT/sof-ipc4
zip $OUT/sof-ipc4.zip sof/tools/corpus/sof-ipc4/*

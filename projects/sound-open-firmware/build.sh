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

cd $SRC/sof/tools/oss-fuzz
cp corpus/* $OUT/
rm -rf build_oss_fuzz
mkdir -p build_oss_fuzz
cd build_oss_fuzz

export VERBOSE=1
cmake -DCMAKE_INSTALL_PREFIX=install -DCMAKE_LINKER=$CXX -DCMAKE_C_LINK_EXECUTABLE="<CMAKE_LINKER> <FLAGS> <CMAKE_C_LINK_FLAGS> <LINK_FLAGS> <OBJECTS> -o <TARGET> <LINK_LIBRARIES>" ..
make install -j $(nproc)

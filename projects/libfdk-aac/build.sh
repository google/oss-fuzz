#!/bin/bash -eu
# Copyright 2019 Google Inc.
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

# Build the lib.
INCLUDES=$(for f in $(find aac -name include); do echo -I $f; done)
# exclude -fno-sanitize=shift-base as there are shallow errors.
EXTRA_FLAGS=-fno-sanitize=shift-base
for f in aac/*/src/*.cpp; do
  $CXX $CXXFLAGS $INCLUDES $EXTRA_FLAGS -c $f &
done
wait

# Build the fuzz targets.
for target_cpp in *.cpp; do
  target=$(basename $target_cpp .cpp)
  $CXX $CXXFLAGS $EXTRA_FLAGS $target_cpp $INCLUDES *.o -lm  $LIB_FUZZING_ENGINE -o $OUT/$target
done

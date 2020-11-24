#!/bin/bash -eu
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

# We dont have getentropy syscall, so always return error when this is issued.
# The result is not breaking, but rather an under-approximation of all the possible states.
sed -i 's/int rc = getentropy(buffer, length);/int rc;\nif (buffer \&\& length) { rc = -1; } else {rc = -1; };/' serenity/AK/Random.h

sed -i 's/if (BUILD_LAGOM)/if (BUILD_LAGOM)\n    add_library(Lagom $<TARGET_OBJECTS:LagomCore> ${LAGOM_MORE_SOURCES})\nendif()\nif(FALSE)/' serenity/Meta/Lagom/CMakeLists.txt

echo "if (ENABLE_OSS_FUZZ)" >> serenity/Meta/Lagom/CMakeLists.txt
echo "    add_subdirectory(Fuzzers)" >> serenity/Meta/Lagom/CMakeLists.txt
echo "endif()" >> serenity/Meta/Lagom/CMakeLists.txt
sed -i 's/-Wall -Wextra -Werror //' serenity/Meta/Lagom/CMakeLists.txt

# Now build the content
cd serenity/Meta/Lagom
mkdir build
cd build
cmake -DBUILD_LAGOM=ON \
    -DENABLE_OSS_FUZZ=ON \
    -DCMAKE_C_COMPILER=$CC \
    -DCMAKE_CXX_COMPILER=$CXX \
    -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
    -DLINKER_FLAGS="$LIB_FUZZING_ENGINE" \
    ..
make
cp Fuzzers/Fuzz* $OUT/


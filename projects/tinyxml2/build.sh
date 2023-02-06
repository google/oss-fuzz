#!/bin/bash
# Copyright 2017 Google Inc.
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

# Make sure OSS-Fuzz's CXXFLAGS are propagated into the build
sed -i 's/CXXFLAGS =/#CXXFLAGS/g' Makefile

make -j$(nproc) clean
make -j$(nproc) all

$CXX $CXXFLAGS -std=c++11 -Iinclude/ $SRC/xmltest.cpp -o $OUT/xmltest \
    $LIB_FUZZING_ENGINE $SRC/tinyxml2/libtinyxml2.a

cp $SRC/*.dict $SRC/*.options $OUT/

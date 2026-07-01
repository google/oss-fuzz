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

# 1. Build Abseil-CPP from source
echo "Building Abseil..."
mkdir -p $SRC/abseil-cpp/build
cd $SRC/abseil-cpp/build
cmake \
  -DCMAKE_CXX_COMPILER=$CXX \
  -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
  -DCMAKE_CXX_STANDARD=20 \
  -DCMAKE_INSTALL_PREFIX=$SRC/abseil_install \
  -DBUILD_TESTING=OFF \
  ..
make -j$(nproc) install

# Go to gbmcweb directory
cd $SRC/gbmcweb

# Fix MutexLock calls (Abseil MutexLock takes a pointer)
find tlbmc -name "*.cc" -o -name "*.h" | xargs sed -i 's/\(absl::\)\?MutexLock\s\+\([a-zA-Z0-9_]*\)\s*(\([^&][^)]*\))/\1MutexLock \2(\&\3)/g'

# Fix missing Boost include in scheduler.h
sed -i '/#include "boost\/asio\/steady_timer.hpp"/a #include <boost/asio/executor_work_guard.hpp>' tlbmc/scheduler/scheduler.h || true

# Workaround for std::result_of in C++20 with older Boost
export CXXFLAGS="$CXXFLAGS -DBOOST_ASIO_HAS_STD_INVOKE_RESULT"

# Compile pacemaker_fuzzer
$CXX $CXXFLAGS -std=c++20 \
  -I. \
  -Itlbmc \
  -I$SRC/abseil_install/include \
  $SRC/pacemaker_fuzzer.cc \
  $(find tlbmc -name "*.cc" ! -name "*test*.cc") \
  -o $OUT/pacemaker_fuzzer \
  $LIB_FUZZING_ENGINE \
  -Wl,--start-group $SRC/abseil_install/lib/libabsl_*.a -Wl,--end-group \
  -lpthread -latomic



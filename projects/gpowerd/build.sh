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

# 2. Build Protobuf from source
echo "Building Protobuf..."
mkdir -p $SRC/protobuf/build
cd $SRC/protobuf/build
cmake \
  -DCMAKE_CXX_COMPILER=$CXX \
  -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
  -DCMAKE_CXX_STANDARD=20 \
  -Dprotobuf_BUILD_TESTS=OFF \
  -DCMAKE_INSTALL_PREFIX=$SRC/protobuf_install \
  ..
make -j$(nproc) install

# Go back to gpowerd directory
cd $SRC/gpowerd

# Translate Protobuf Editions (2023) to proto2
python3 $SRC/translate_protos.py

# Fix compatibility issues in source files
# Convert absl::string_view to std::string for set_message in convert_proto.cc
sed -i 's/status.message()/std::string(status.message())/g' convert_proto.cc

# Convert absl::string_view to std::string for map find() in action_validation.cc
sed -i 's/find(node_entity_tag)/find(std::string(node_entity_tag))/g' action_validation.cc

# Fix absl::StrFormat of absl::Time in action_validation.cc
python3 -c "
import re
with open('action_validation.cc', 'r') as f:
  content = f.read()
content = re.sub(
    r'timeout = %v\",\s*start_time \+ max_timeout',
    'timeout = %s\",\n                      absl::FormatTime(start_time + max_timeout)',
    content
)
with open('action_validation.cc', 'w') as f:
  f.write(content)
"

# Replace try_lock/unlock with WriterTryLock/WriterUnlock on absl::Mutex in state_updater.h
sed -i 's/listeners_mutex_.try_lock()/listeners_mutex_.WriterTryLock()/g' state_updater.h
sed -i 's/listeners_mutex_.unlock()/listeners_mutex_.WriterUnlock()/g' state_updater.h

# Add & to MutexLock calls in all C++ files (older Abseil MutexLock takes a pointer)
sed -i 's/\(absl::\)\?MutexLock\s\+\([a-zA-Z0-9_]*\)\s*(\([^)]*\))/\1MutexLock \2(\&\3)/g' *.cc *.h

# Use ShortDebugString() for protobuf messages in absl::StrCat in condition.cc
sed -i 's/Abort condition matched: ", condition/Abort condition matched: ", condition.ShortDebugString()/g' condition.cc
sed -i 's/Unknown timeout type: ", condition/Unknown timeout type: ", condition.ShortDebugString()/g' condition.cc
sed -i 's/Unknown condition type: ", condition/Unknown condition type: ", condition.ShortDebugString()/g' condition.cc

# Compile protobufs using the newly built protoc
$SRC/protobuf_install/bin/protoc --cpp_out=. -Iproto proto/*.proto

# Get compiler and linker flags for OpenSSL (system library, C-based so no ABI issue)
OPENSSL_FLAGS=$(pkg-config --cflags --libs openssl)

# Compile action_validation_fuzzer
$CXX $CXXFLAGS -std=c++20 \
  -I. \
  -Iproto \
  -Ibmc \
  -I$SRC/gpowerd_shims \
  -I$SRC/abseil_install/include \
  -I$SRC/protobuf_install/include \
  *.pb.cc \
  action_validation.cc \
  condition.cc \
  state_merge.cc \
  convert_proto.cc \
  daemon_context.cc \
  callback_manager.cc \
  $SRC/action_validation_fuzzer.cc \
  -o $OUT/action_validation_fuzzer \
  $LIB_FUZZING_ENGINE \
  $SRC/protobuf_install/lib/libprotobuf.a \
  -Wl,--start-group $SRC/abseil_install/lib/libabsl_*.a -Wl,--end-group \
  $OPENSSL_FLAGS

# Compile condition_fuzzer
$CXX $CXXFLAGS -std=c++20 \
  -I. \
  -Iproto \
  -Ibmc \
  -I$SRC/gpowerd_shims \
  -I$SRC/abseil_install/include \
  -I$SRC/protobuf_install/include \
  *.pb.cc \
  action_validation.cc \
  condition.cc \
  state_merge.cc \
  convert_proto.cc \
  daemon_context.cc \
  callback_manager.cc \
  $SRC/condition_fuzzer.cc \
  -o $OUT/condition_fuzzer \
  $LIB_FUZZING_ENGINE \
  $SRC/protobuf_install/lib/libprotobuf.a \
  -Wl,--start-group $SRC/abseil_install/lib/libabsl_*.a -Wl,--end-group \
  $OPENSSL_FLAGS

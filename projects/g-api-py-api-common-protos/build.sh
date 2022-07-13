#!/bin/bash -eu
# Copyright 2022 Google LLC
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

# Build protoc with default options.
unset CFLAGS CXXFLAGS
mkdir $SRC/protobuf-install/
cd $SRC/protobuf/
./autogen.sh
./configure --prefix=$SRC/protobuf-install
make -j$(nproc)
make install
export PROTOC="$SRC/protobuf-install/bin/protoc"

ldconfig
cd python
python3 setup.py build --cpp_implementation
pip3 install .

# Compile .proto specs
cd $SRC/python-api-common-protos/
for target in quota billing service routing log; do
  $PROTOC --python_out=. --proto_path=. google/api/$target.proto
done

# Compile fuzzer
for fuzzer in $(find $SRC -name 'fuzz_*.py'); do
  compile_python_fuzzer $fuzzer
done

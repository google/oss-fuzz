#!/bin/bash -eu
# Copyright 2021 Google LLC
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

# build project
export ASAN_OPTIONS=detect_leaks=0

if [ "$SANITIZER" = "coverage" ]
then
    cp /usr/bin/ld.gold /usr/bin/ld
fi
./bootstrap.sh
# rust fails compilation with clippy warnings
./configure --with-rs=no
make -j$(nproc)
make install

cd lib/go/test/fuzz
thrift -r --gen go ../../../../tutorial/tutorial.thrift
(cd ./gen-go/shared && go mod init shared)
(cd ./gen-go/tutorial && go mod init tutorial)
go mod tidy || true
compile_go_fuzzer . Fuzz fuzz_go_tutorial

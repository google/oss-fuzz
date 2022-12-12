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

printf "package peer\nimport _ \"github.com/AdamKorcz/go-118-fuzz-build/testing\"\n" > $SRC/go-libp2p/core/peer/registerfuzzdep.go
go mod tidy && go mod vendor
cp $SRC/encode_decode_fuzz.go $SRC/go-libp2p/core/peer/
compile_native_go_fuzzer ./core/peer FuzzEncodeDecodeID FuzzEncodeDecodeID

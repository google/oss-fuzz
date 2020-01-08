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

# We've used git checkout, not go get to fetch the source so set up the GOPATH to find our source.
export GOPATH=$GOPATH:/

# go-fuzz-build doesn't like modules until https://github.com/dvyukov/go-fuzz/issues/195 is fixed
# fetch and vendor all the dependencies so go-fuzz-build can find them
make GO111MODULE=off --debug install_deps
go mod vendor

make GO111MODULE=off --debug $OUT/vm-fuzzer.dict $OUT/vm-fuzzer_seed_corpus.zip $OUT/vm-fuzzer

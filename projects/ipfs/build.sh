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

cd $GOPATH/src/github.com/ipfs/go-datastore/fuzz
DS_PROVIDERS="github.com/ipfs/go-ds-badger,github.com/ipfs/go-ds-badger2" go generate

# vendor dependencies since go-fuzz doesn't play nicely with go mod.
go mod vendor
mkdir .gopath
cd .gopath
ln -s ../vendor src
cd ..

fuzzer="ipfs_ds_fuzzer"
# Compile and instrument all Go files relevant to this fuzz target.
GO111MODULE=off GOPATH=$PWD/.gopath go-fuzz -o $fuzzer.a .

# Link Go code ($fuzzer.a) with fuzzing engine to produce fuzz target binary.
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE $fuzzer.a -o $OUT/$fuzzer

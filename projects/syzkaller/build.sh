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

# Bootstrap the latest go.
pushd $SRC
rm -rf go
git clone --depth 1 https://github.com/golang/go go
pushd go/src/
./make.bash
popd
popd

# Remove golang used to bootstrap the latest version.
apt-get remove golang-1.10-go -y
rm /usr/bin/go

# Set up Golang env variables.
export GOROOT="$SRC/go"
export GOPATH="$GOROOT/packages"
export PATH="$PATH:$GOROOT/bin:$GOPATH/bin"

# Dependency of go-fuzz
go get golang.org/x/tools/go/packages

# go-fuzz-build is the tool that instruments Go files.
go get github.com/dvyukov/go-fuzz/go-fuzz-build

# Based on the function from oss-fuzz/projects/golang/build.sh script.
function compile_fuzzer {
  path=$1
  function=$2
  fuzzer=$3

   # Instrument all Go files relevant to this fuzzer
  go-fuzz-build -libfuzzer -func $function -o $fuzzer.a $path 

   # Instrumented, compiled Go ($fuzzer.a) + fuzzing engine = fuzzer binary
  $CXX $CXXFLAGS $LIB_FUZZING_ENGINE $fuzzer.a -lpthread -o $OUT/$fuzzer
}

compile_fuzzer ./pkg/compiler Fuzz compiler_fuzzer
compile_fuzzer ./prog/test FuzzDeserialize prog_deserialize_fuzzer
compile_fuzzer ./prog/test FuzzParseLog prog_parselog_fuzzer
compile_fuzzer ./pkg/report Fuzz report_fuzzer
compile_fuzzer ./tools/syz-trace2syz/proggen Fuzz trace2syz_fuzzer

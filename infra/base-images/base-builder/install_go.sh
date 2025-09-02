#!/bin/bash -eux
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

cd /tmp

wget https://go.dev/dl/go1.23.4.linux-amd64.tar.gz
mkdir temp-go
tar -C temp-go/ -xzf go1.23.4.linux-amd64.tar.gz

mkdir /root/.go/
mv temp-go/go/* /root/.go/
rm -rf temp-go

echo 'Set "GOPATH=/root/go"'
echo 'Set "PATH=$PATH:/root/.go/bin:$GOPATH/bin"'

go install github.com/mdempsky/go114-fuzz-build@latest
ln -s $GOPATH/bin/go114-fuzz-build $GOPATH/bin/go-fuzz

# Build signal handler
if [ -f "$GOPATH/gosigfuzz/gosigfuzz.c" ]; then
    clang -c $GOPATH/gosigfuzz/gosigfuzz.c -o $GOPATH/gosigfuzz/gosigfuzz.o
fi

cd /tmp
git clone https://github.com/AdamKorcz/go-118-fuzz-build
cd go-118-fuzz-build
go build
mv go-118-fuzz-build $GOPATH/bin/

# Build v2 binaries
git checkout v2
go build .
mv go-118-fuzz-build $GOPATH/bin/go-118-fuzz-build_v2
pushd cmd/convertLibFuzzerTestcaseToStdLibGo
  go build . && mv convertLibFuzzerTestcaseToStdLibGo $GOPATH/bin/
popd
pushd cmd/addStdLibCorpusToFuzzer
  go build . && mv addStdLibCorpusToFuzzer $GOPATH/bin/
popd
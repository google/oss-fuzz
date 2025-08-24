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

mv $SRC/thorchain/fuzzers $GOPATH/src/gitlab.com/thorchain/thornode
# Set go-ethereum to a newer version which fixes fuzzer breakage
sed -i 's#github.com/ethereum/go-ethereum v1.10.4#github.com/ethereum/go-ethereum v1.10.9#g' $GOPATH/src/gitlab.com/thorchain/thornode/go.mod

compile_go_fuzzer gitlab.com/thorchain/thornode/fuzzers/memo Fuzz memo-fuzzer
zip memo_seed_corpus.zip $GOPATH/src/gitlab.com/thorchain/thornode/fuzzers/memo/corp
cp $GOPATH/src/gitlab.com/thorchain/thornode/fuzzers/memo/memo.dict $OUT/memo-fuzzer.dict

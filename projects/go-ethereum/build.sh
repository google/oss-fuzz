#/bin/bash -eu
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
function compile_fuzzer {
  path=$1
  function=$2
  fuzzer=$3

  go-fuzz -func $function -o $fuzzer.a $path

  $CXX $CXXFLAGS $LIB_FUZZING_ENGINE $fuzzer.a -o $OUT/$fuzzer
}

cd $GOPATH/src/github.com/ethereum/go-ethereum
make all

cd $SRC


compile_fuzzer github.com/ethereum/go-ethereum/common/bitutil Fuzz fuzzBitutilCompress
compile_fuzzer github.com/ethereum/go-ethereum/crypto/bn256 FuzzAdd fuzzAdd
compile_fuzzer github.com/ethereum/go-ethereum/crypto/bn256 FuzzMul fuzzMul
compile_fuzzer github.com/ethereum/go-ethereum/crypto/bn256 FuzzPair fuzzPair
compile_fuzzer github.com/ethereum/go-ethereum/core/vm/runtime Fuzz fuzzVmRuntime
compile_fuzzer github.com/ethereum/go-ethereum/crypto/blake2b Fuzz fuzzBlake2b
compile_fuzzer github.com/ethereum/go-ethereum/tests/fuzzers/keystore Fuzz fuzzKeystore
compile_fuzzer github.com/ethereum/go-ethereum/tests/fuzzers/txfetcher Fuzz fuzzTxfetcher
#compile_fuzzer github.com/ethereum/go-ethereum/tests/fuzzers/abi Fuzz fuzzAbi
compile_fuzzer github.com/ethereum/go-ethereum/tests/fuzzers/rlp Fuzz fuzzRlp
compile_fuzzer github.com/ethereum/go-ethereum/tests/fuzzers/trie Fuzz fuzzTrie


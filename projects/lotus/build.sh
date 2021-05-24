#!/bin/bash -eu
# Copyright 2021 Google LLC.
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

make

# Not all fuzzers can be compiled with --sanitizer=coverage.
# The specific issue is that gofuzz.NewFromGofuzz is not supported when compiling with coverage.
# The current status of the coverage build is that we do not break it for the fuzzers that cannot be compiled.
#The reason that we don't break the build script is to create coverage reports for the fuzzers that compile.
if [[ $SANITIZER = *coverage* ]]; then
	compile_go_fuzzer github.com/filecoin-project/lotus/chain/types FuzzMessage fuzz_message gofuzz
	mkdir fuzzing
	cp ../fuzzing-lotus/fuzz/fuzz.go fuzzing/
	compile_go_fuzzer github.com/filecoin-project/lotus/fuzzing FuzzBlockMsg fuzz_block_msg || true
	compile_go_fuzzer github.com/filecoin-project/lotus/fuzzing FuzzBlockMsgStructural fuzz_block_msg_structural || true
	compile_go_fuzzer github.com/filecoin-project/lotus/fuzzing FuzzBlockHeader fuzz_block_header || true
	compile_go_fuzzer github.com/filecoin-project/lotus/fuzzing FuzzNodesForHeight fuzz_nodes_for_height || true
	exit 0
fi

compile_go_fuzzer ./chain/types FuzzMessage fuzz_message gofuzz


# Fuzzers from fuzzing-lotus
cd ../fuzzing-lotus/fuzz
rm -Rf libfuzzer
go mod init github.com/filecoin-project/fuzzing-lotus/fuzz

compile_go_fuzzer github.com/filecoin-project/fuzzing-lotus/fuzz FuzzBlockMsg fuzz_block_msg
compile_go_fuzzer github.com/filecoin-project/fuzzing-lotus/fuzz FuzzBlockMsgStructural fuzz_block_msg_structural
compile_go_fuzzer github.com/filecoin-project/fuzzing-lotus/fuzz FuzzBlockHeader fuzz_block_header
compile_go_fuzzer github.com/filecoin-project/fuzzing-lotus/fuzz FuzzNodesForHeight fuzz_nodes_for_height
exit 0

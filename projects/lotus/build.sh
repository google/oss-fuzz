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

compile_go_fuzzer github.com/filecoin-project/lotus/chain/types FuzzMessage fuzz_message gofuzz
compile_go_fuzzer github.com/filecoin-project/fuzzing-lotus/fuzz FuzzBlockMsg fuzz_block_msg
compile_go_fuzzer github.com/filecoin-project/fuzzing-lotus/fuzz FuzzBlockMsgStructural fuzz_block_msg_structural
compile_go_fuzzer github.com/filecoin-project/fuzzing-lotus/fuzz FuzzBlockHeader fuzz_block_header
compile_go_fuzzer github.com/filecoin-project/fuzzing-lotus/fuzz FuzzNodesForHeight fuzz_nodes_for_height

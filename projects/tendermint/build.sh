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
compile_go_fuzzer github.com/tendermint/tendermint/test/fuzz/mempool/v0 Fuzz mempool_v0_fuzzer
compile_go_fuzzer github.com/tendermint/tendermint/test/fuzz/mempool/v1 Fuzz mempool_v1_fuzzer
compile_go_fuzzer github.com/tendermint/tendermint/test/fuzz/p2p/addrbook Fuzz p2p_addrbook_fuzzer
compile_go_fuzzer github.com/tendermint/tendermint/test/fuzz/p2p/pex Fuzz p2p_pex_fuzzer
compile_go_fuzzer github.com/tendermint/tendermint/test/fuzz/rpc/jsonrpc/server Fuzz rpc_jsonrpc_server_fuzzer

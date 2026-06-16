#!/bin/bash -eu
# Copyright 2026 Google LLC
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

# Usage: compile_native_go_fuzzer <package-import-path> <FuzzFunc> <output-name>
#
# Each Erigon fuzz target is a native Go fuzzer (`func FuzzXxx(f *testing.F)`)
# living in a *_test.go file. The output name must be unique per binary.

MOD=github.com/erigontech/erigon

# compile_native_go_fuzzer rewrites each testing.F fuzzer through
# go-118-fuzz-build, which imports this shim in place of stdlib testing. It must
# be resolvable in the module graph. Add it here only (not via `go mod tidy`,
# which would drop it since no Erigon source imports it).
go get github.com/AdamKorcz/go-118-fuzz-build/testing

# --- Pure-Go targets (no cgo) ---------------------------------------------

compile_native_go_fuzzer $MOD/common/bitutil           FuzzEncoder              fuzz_bitutil_encoder
compile_native_go_fuzzer $MOD/common/bitutil           FuzzDecoder              fuzz_bitutil_decoder

compile_native_go_fuzzer $MOD/db/datastruct/fusefilter FuzzReaderOnBytes        fuzz_fusefilter_reader
compile_native_go_fuzzer $MOD/db/datastruct/fusefilter FuzzReaderShardedOnBytes fuzz_fusefilter_reader_sharded
compile_native_go_fuzzer $MOD/db/datastruct/fusefilter FuzzWriterRoundTrip      fuzz_fusefilter_writer_roundtrip

compile_native_go_fuzzer $MOD/db/recsplit/eliasfano16  FuzzSingleEliasFano      fuzz_ef16_single
compile_native_go_fuzzer $MOD/db/recsplit/eliasfano16  FuzzDoubleEliasFano      fuzz_ef16_double
compile_native_go_fuzzer $MOD/db/recsplit/eliasfano32  FuzzSingleEliasFano      fuzz_ef32_single
compile_native_go_fuzzer $MOD/db/recsplit/eliasfano32  FuzzDoubleEliasFano      fuzz_ef32_double

compile_native_go_fuzzer $MOD/db/recsplit              FuzzRecSplit             fuzz_recsplit

compile_native_go_fuzzer $MOD/db/seg                   FuzzCompress             fuzz_seg_compress
compile_native_go_fuzzer $MOD/db/seg                   FuzzDecompressMatch      fuzz_seg_decompress_match
compile_native_go_fuzzer $MOD/db/seg/patricia          FuzzPatricia             fuzz_patricia
compile_native_go_fuzzer $MOD/db/seg/patricia          FuzzLongestMatch         fuzz_patricia_longest_match

compile_native_go_fuzzer $MOD/execution/commitment/nibbles FuzzHexCompactRoundtrip fuzz_nibbles_hexcompact

# --- cgo via secp256k1 only (small C lib; same footprint as go-ethereum) ---

compile_native_go_fuzzer $MOD/execution/abi            FuzzABI                  fuzz_abi
compile_native_go_fuzzer $MOD/execution/types          FuzzRLP                  fuzz_rlp
compile_native_go_fuzzer $MOD/execution/vm             FuzzPrecompiledContracts fuzz_precompiles
compile_native_go_fuzzer $MOD/execution/vm/runtime     FuzzVmRuntime            fuzz_vm_runtime

# --- Deferred: cgo + MDBX (txnprovider/txpool) -----------------------------
#
# The txpool fuzzers (FuzzParseTx, FuzzPooledTransactions66,
# FuzzGetPooledTransactions66, FuzzOnNewBlocks) transitively link the MDBX C
# library, which needs validating under the OSS-Fuzz sanitizer toolchain
# before being enabled. Add in a follow-up once the build is confirmed green:
#
# compile_native_go_fuzzer $MOD/txnprovider/txpool FuzzParseTx                  fuzz_txpool_parsetx
# compile_native_go_fuzzer $MOD/txnprovider/txpool FuzzPooledTransactions66     fuzz_txpool_pooledtxns66
# compile_native_go_fuzzer $MOD/txnprovider/txpool FuzzGetPooledTransactions66  fuzz_txpool_getpooledtxns66
# compile_native_go_fuzzer $MOD/txnprovider/txpool FuzzOnNewBlocks              fuzz_txpool_onnewblocks

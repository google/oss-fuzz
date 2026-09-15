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

# Enabled targets: native fuzzers verified to compile both under
# go-118-fuzz-build (libfuzzer/sanitizer builds) and under the CGO-disabled
# coverage build. New targets are added once their blocker (below) is cleared.

compile_native_go_fuzzer $MOD/db/datastruct/fusefilter FuzzReaderOnBytes        fuzz_fusefilter_reader
compile_native_go_fuzzer $MOD/db/datastruct/fusefilter FuzzReaderShardedOnBytes fuzz_fusefilter_reader_sharded
compile_native_go_fuzzer $MOD/db/datastruct/fusefilter FuzzWriterRoundTrip      fuzz_fusefilter_writer_roundtrip

compile_native_go_fuzzer $MOD/db/recsplit/eliasfano16  FuzzSingleEliasFano      fuzz_ef16_single
compile_native_go_fuzzer $MOD/db/recsplit/eliasfano16  FuzzDoubleEliasFano      fuzz_ef16_double
compile_native_go_fuzzer $MOD/db/recsplit/eliasfano32  FuzzSingleEliasFano      fuzz_ef32_single
compile_native_go_fuzzer $MOD/db/recsplit/eliasfano32  FuzzDoubleEliasFano      fuzz_ef32_double

compile_native_go_fuzzer $MOD/db/seg/patricia          FuzzPatricia             fuzz_patricia
compile_native_go_fuzzer $MOD/db/seg/patricia          FuzzLongestMatch         fuzz_patricia_longest_match

compile_native_go_fuzzer $MOD/execution/abi            FuzzABI                  fuzz_abi

# --- Deferred targets ------------------------------------------------------
# These build under plain `go test` but not yet under the OSS-Fuzz toolchain.
# Re-enable each as its blocker is resolved.
#
# (a) go-118-fuzz-build's testing shim has no testing.B, and these fuzzers
#     share a file with benchmarks. Fix: move the fuzzer into a benchmark-free
#     file upstream, then enable here.
#       $MOD/common/bitutil                FuzzEncoder, FuzzDecoder
#       $MOD/execution/commitment/nibbles  FuzzHexCompactRoundtrip
#
# (b) The shim's testing.T has no Context() method (Go 1.24+), used in these
#     fuzzer files.
#       $MOD/db/recsplit                   FuzzRecSplit
#       $MOD/db/seg                        FuzzCompress, FuzzDecompressMatch
#
# (c) Require cgo, but the OSS-Fuzz coverage build runs with CGO disabled
#     (undefined secp256k1 symbols). Needs the coverage build to allow cgo, or
#     these excluded from coverage.
#       $MOD/execution/types               FuzzRLP
#       $MOD/execution/vm                  FuzzPrecompiledContracts
#       $MOD/execution/vm/runtime          FuzzVmRuntime
#
# (d) cgo + MDBX (large C lib), needs sanitizer-toolchain validation.
#       $MOD/txnprovider/txpool  FuzzParseTx, FuzzPooledTransactions66,
#                                FuzzGetPooledTransactions66, FuzzOnNewBlocks

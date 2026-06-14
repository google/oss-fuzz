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
#
################################################################################

cd "$SRC/zstd-seekable-format-go/pkg"

# The native Go fuzzer helper rewrites _test.go files into regular Go files.
# Keep external-package examples out of package-local fuzz builds.
rm example_test.go
rm framecache/example_test.go

FUZZERS_PACKAGE=github.com/SaveTheRbtz/zstd-seekable-format-go/pkg
FRAMECACHE_FUZZERS_PACKAGE="$FUZZERS_PACKAGE/framecache"

compile_native_go_fuzzer_v2 "$FUZZERS_PACKAGE" FuzzReader FuzzReader
compile_native_go_fuzzer_v2 "$FUZZERS_PACKAGE" FuzzReaderConst FuzzReaderConst
compile_native_go_fuzzer_v2 "$FUZZERS_PACKAGE" FuzzRoundTrip FuzzRoundTrip
compile_native_go_fuzzer_v2 "$FUZZERS_PACKAGE" FuzzCorruptSeekTable FuzzCorruptSeekTable
compile_native_go_fuzzer_v2 "$FUZZERS_PACKAGE" FuzzReaderFrameCacheConcurrentReadAt FuzzReaderFrameCacheConcurrentReadAt
compile_native_go_fuzzer_v2 "$FRAMECACHE_FUZZERS_PACKAGE" FuzzFrameCacheAccessPatterns FuzzFrameCacheAccessPatterns

zip -j "$OUT/FuzzReader_seed_corpus.zip" testdata/fuzz/FuzzReader/*
zip -j "$OUT/FuzzRoundTrip_seed_corpus.zip" testdata/fuzz/FuzzRoundTrip/*

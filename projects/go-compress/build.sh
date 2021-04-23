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

compile_go_fuzzer github.com/klauspost/compress/fuzz/flate Fuzz fuzz_flate
compile_go_fuzzer github.com/klauspost/compress/fuzz/fse FuzzCompress fuzz_fse_compress
compile_go_fuzzer github.com/klauspost/compress/fuzz/fse FuzzDecompress fuzz_fse_decompress
compile_go_fuzzer github.com/klauspost/compress/fuzz/huff0 FuzzCompress fuzz_huff0_compress
compile_go_fuzzer github.com/klauspost/compress/fuzz/huff0 FuzzDecompress fuzz_huff0_decompress
#compile_go_fuzzer github.com/klauspost/compress/fuzz/s2 FuzzCompress fuzz_s2_compress
#compile_go_fuzzer github.com/klauspost/compress/fuzz/s2 FuzzDecompress fuzz_s2_decompress
compile_go_fuzzer github.com/klauspost/compress/fuzz/zstd FuzzCompress fuzz_zstd_compress
#compile_go_fuzzer github.com/klauspost/compress/fuzz/zstd FuzzCompressRef fuzz_zstd_compress_ref datadog
#compile_go_fuzzer github.com/klauspost/compress/fuzz/zstd FuzzCompressSimple fuzz_zstd_compress_simple
compile_go_fuzzer github.com/klauspost/compress/fuzz/zstd FuzzDecompress fuzz_zstd_decompress
#compile_go_fuzzer github.com/klauspost/compress/fuzz/zstd FuzzDecompressRef fuzz_zstd_decompress_ref datadog

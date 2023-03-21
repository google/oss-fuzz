#!/bin/bash -eu
# Copyright 2023 Google LLC
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

# In one of the Zstd fuzzers, the "dict" variable is created by reading a series of files.
# These files are not available at runtime in the OSS-FUzz environment,
# so we add the contents of these files to a variable and create a new file
# that is included when we build the fuzzers in OSS-Fuzz.
mkdir $SRC/setupdicts
cp $SRC/setup_dicts.go $SRC/setupdicts/main.go
cd $SRC/setupdicts
go mod init setupdicts
go mod tidy
go run main.go --dict-path=$SRC/compress/zstd/testdata/dict-tests-small.zip --output-file=$SRC/compress/zstd/fuzzDicts.go
cp $SRC/compress/zstd/fuzzDicts.go $OUT/
# Done creating "dicts" variable.

cd $SRC/compress

# Temporarily use a fork of go-fuzz-headers with some improvements that has not been merged yet.
go mod edit -replace github.com/AdaLogics/go-fuzz-headers=github.com/AdamKorcz/go-fuzz-headers-1@22e92b7968997eabd210694dd4825dd0d19b697c

# Modify some files. This would be better done upstream.
sed -i '38 a\
	if fi == nil { return }' $SRC/compress/internal/fuzz/helpers.go
printf "package compress\nimport _ \"github.com/AdamKorcz/go-118-fuzz-build/testing\"\n" > registerfuzzdependency.go
sed -i 's/zr := testCreateZipReader/\/\/zr := testCreateZipReader/g' "${SRC}"/compress/zstd/fuzz_test.go
sed -i 's/dicts = readDicts(f, zr)/dicts = fuzzDicts/g' "${SRC}"/compress/zstd/fuzz_test.go

if [ "$SANITIZER" != "coverage" ]; then
	sed -i 's/\"testing\"/\"github.com\/AdamKorcz\/go-118-fuzz-build\/testing\"/g' "${SRC}"/compress/internal/fuzz/helpers.go
fi

# OSS-Fuzz uses 'go build' to build the fuzzers, so we move the tests
# we need into scope.
mv $SRC/compress/zstd/decoder_test.go $SRC/compress/zstd/decoder_test_fuzz.go
mv $SRC/compress/zstd/zstd_test.go $SRC/compress/zstd/zstd_test_fuzz.go
mv $SRC/compress/zstd/seqdec_test.go $SRC/compress/zstd/seqdec_test_fuzz.go
mv $SRC/compress/zstd/dict_test.go $SRC/compress/zstd/dict_test_fuzz.go
mv $SRC/compress/s2/s2_test.go $SRC/compress/s2/s2_test_fuzz.go
go mod tidy

# Build fuzzers
compile_native_go_fuzzer github.com/klauspost/compress/flate FuzzEncoding FuzzFlateEncoding
compile_native_go_fuzzer github.com/klauspost/compress/zstd FuzzDecodeAll FuzzDecodeAll
compile_native_go_fuzzer github.com/klauspost/compress/zstd FuzzDecAllNoBMI2 FuzzDecAllNoBMI2
compile_native_go_fuzzer github.com/klauspost/compress/zstd FuzzDecoder FuzzDecoder
compile_native_go_fuzzer github.com/klauspost/compress/zstd FuzzNoBMI2Dec FuzzNoBMI2Dec
compile_native_go_fuzzer github.com/klauspost/compress/zstd FuzzEncoding FuzzZstdEncoding
#compile_native_go_fuzzer github.com/klauspost/compress/s2 FuzzLZ4Block FuzzLZ4Block
#compile_native_go_fuzzer github.com/klauspost/compress/s2 FuzzDictBlocks FuzzDictBlocks
#compile_native_go_fuzzer github.com/klauspost/compress/s2 FuzzEncodingBlocks FuzzEncodingBlocks
compile_native_go_fuzzer github.com/klauspost/compress/zip FuzzReader FuzzReader

# Add corpora
cp $SRC/compress/zstd/testdata/fuzz/encode-corpus-raw.zip $OUT/FuzzZstdEncoding_seed_corpus.zip
cp $SRC/compress/zstd/testdata/fuzz/decode-corpus-raw.zip $OUT/FuzzDecodeAll_seed_corpus.zip
cp $SRC/compress/zstd/testdata/fuzz/decode-corpus-raw.zip $OUT/FuzzDecoder_seed_corpus.zip
cp $SRC/compress/zip/testdata/FuzzReader-raw.zip $OUT/FuzzReader_seed_corpus.zip

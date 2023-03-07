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

# Temporarily disable coverage build in OSS-Fuzz's CI
if [ -n "${OSS_FUZZ_CI-}" ]
then
	if [ "${SANITIZER}" = 'coverage' ]
	then
		exit 0
	fi

fi

export FUZZ_ROOT="github.com/dvyukov/go-fuzz-corpus"

cd $SRC/text
cp $SRC/unicode_fuzzer.go ./encoding/unicode/
find . -name "*_test.go" ! -name 'fuzz_test.go' -type f -exec rm -f {} +
compile_go_fuzzer golang.org/x/text/encoding/unicode FuzzUnicodeTransform fuzz_unicode_transform

function setup_golang_fuzzers() {
	cd $SRC/golang
	# These two directories cause build issues and are not used by oss-fuzz.
	# They can be removed:
	rm -r sqlparser
	rm -r parser

	mkdir $SRC/golang/math && cp $SRC/math_big_fuzzer.go $SRC/golang/math/

	mkdir $SRC/golang/text && cp $SRC/text_fuzzer.go $SRC/golang/text/
	cp $SRC/language_fuzzer.go $SRC/golang/text/

	mkdir -p $SRC/golang/crypto/x509
	cp $SRC/x509_fuzzer.go $SRC/golang/crypto/x509/

	mkdir -p $SRC/golang/crypto/ecdsa
	cp $SRC/ecdsa_fuzzer.go ./crypto/ecdsa/

	mkdir -p $SRC/golang/crypto/aes
	cp $SRC/aes_fuzzer.go ./crypto/aes/

	mkdir $SRC/golang/fp
	cp $SRC/filepath_fuzzer.go $SRC/golang/fp/

	cp $SRC/strings_fuzzer.go $SRC/golang/strings/

	cp $SRC/multipart_fuzzer.go $SRC/golang/multipart/main.go

	mkdir $SRC/golang/encoding && cp $SRC/encoding_fuzzer.go $SRC/golang/encoding/

	go mod init "github.com/dvyukov/go-fuzz-corpus"
}

function compile_fuzzers() {
	# version is used as suffix for the binaries
	version=$1
	compile_go_fuzzer $FUZZ_ROOT/encoding FuzzEncoding fuzz_encoding$version
	compile_go_fuzzer $FUZZ_ROOT/strings FuzzStringsSplit fuzz_strings_split$version
	compile_go_fuzzer $FUZZ_ROOT/fp FuzzFpGlob glob_fuzzer$version
	compile_go_fuzzer $FUZZ_ROOT/crypto/x509 FuzzParseCert fuzz_parse_cert$version
	compile_go_fuzzer $FUZZ_ROOT/crypto/x509 FuzzPemDecrypt fuzz_pem_decrypt$version
	compile_go_fuzzer $FUZZ_ROOT/crypto/aes FuzzAesCipherDecrypt fuzz_aes_cipher_decrypt$version
	compile_go_fuzzer $FUZZ_ROOT/crypto/aes FuzzAesCipherEncrypt fuzz_aes_cipher_encrypt$version
	compile_go_fuzzer $FUZZ_ROOT/crypto/ecdsa FuzzEcdsaSign FuzzEcdsaSign$version
	compile_go_fuzzer $FUZZ_ROOT/text FuzzAcceptLanguage accept_language_fuzzer$version
	compile_go_fuzzer $FUZZ_ROOT/text FuzzMultipleParsers fuzz_multiple_parsers$version
	compile_go_fuzzer $FUZZ_ROOT/text FuzzCurrency currency_fuzzer$version
	compile_go_fuzzer $FUZZ_ROOT/math FuzzFloatSetString fuzz_float_set_string$version
	compile_go_fuzzer $FUZZ_ROOT/math FuzzBigGobdecode fuzz_big_gobdecode$version
	compile_go_fuzzer $FUZZ_ROOT/math FuzzBigIntCmp1 big_cmp_fuzzer1$version
	compile_go_fuzzer $FUZZ_ROOT/math FuzzBigIntCmp2 big_cmp_fuzzer2$version
	compile_go_fuzzer $FUZZ_ROOT/math FuzzRatSetString big_rat_fuzzer$version
	compile_go_fuzzer $FUZZ_ROOT/math FuzzFloat64SpecialCases fuzz_float64_special_cases$version
	compile_go_fuzzer $FUZZ_ROOT/asn1 Fuzz asn_fuzzer$version
	compile_go_fuzzer $FUZZ_ROOT/csv Fuzz csv_fuzzer$version
	compile_go_fuzzer $FUZZ_ROOT/elliptic Fuzz elliptic_fuzzer$version
	compile_go_fuzzer $FUZZ_ROOT/flate Fuzz flate_fuzzer$version
	compile_go_fuzzer $FUZZ_ROOT/fmt Fuzz fmt_fuzzer$version
	compile_go_fuzzer $FUZZ_ROOT/gzip Fuzz gzip_fuzzer$version
	compile_go_fuzzer $FUZZ_ROOT/httpreq Fuzz httpreq_fuzzer$version
	compile_go_fuzzer $FUZZ_ROOT/jpeg Fuzz jpeg_fuzzer$version
	compile_go_fuzzer $FUZZ_ROOT/json Fuzz json_fuzzer$version
	compile_go_fuzzer $FUZZ_ROOT/lzw Fuzz lzw_fuzzer$version
	compile_go_fuzzer $FUZZ_ROOT/mime Fuzz mime_fuzzer$version
	compile_go_fuzzer $FUZZ_ROOT/multipart Fuzz multipart_fuzzer$version
	compile_go_fuzzer $FUZZ_ROOT/png Fuzz png_fuzzer$version
	compile_go_fuzzer $FUZZ_ROOT/tar Fuzz tar_fuzzer$version
	compile_go_fuzzer $FUZZ_ROOT/time Fuzz time_fuzzer$version
	compile_go_fuzzer $FUZZ_ROOT/xml Fuzz xml_fuzzer$version
	compile_go_fuzzer $FUZZ_ROOT/zip Fuzz zip_fuzzer$version
	compile_go_fuzzer $FUZZ_ROOT/zlib Fuzz zlib_fuzzer$version

	zip $OUT/fuzz_pem_decrypt${version}_seed_corpus.zip $SRC/go/src/crypto/x509/testdata/*
	zip $OUT/fuzz_parse_cert${version}_seed_corpus.zip $SRC/go/src/crypto/x509/testdata/*
}


# Build fuzzers with Go 1.18
setup_golang_fuzzers
compile_fuzzers ""

cd $SRC/go/src/regexp
cp $SRC/regexp_fuzzer.go ./
go mod init regexpPackage
go mod tidy
find . -name "*_test.go" ! -name 'fuzz_test.go' -type f -exec rm -f {} +
compile_go_fuzzer regexpPackage FuzzCompile fuzz_regexp_compile
compile_go_fuzzer regexpPackage FuzzCompilePOSIX fuzz_compile_posix
compile_go_fuzzer regexpPackage FuzzReplaceAll fuzz_replace_all
compile_go_fuzzer regexpPackage FuzzFindMatchApis fuzz_find_match_apis

#cd $SRC/go/src/archive/tar
#go mod init tarPackage
#go mod tidy
#find . -name "*_test.go" ! -name 'fuzz_test.go' -type f -exec rm -f {} +
#go get github.com/AdamKorcz/go-118-fuzz-build/testingtypes
#go get github.com/AdamKorcz/go-118-fuzz-build/utils
#compile_native_go_fuzzer tarPackage FuzzReader fuzz_std_lib_tar_reader
#zip $OUT/fuzz_std_lib_tar_reader_seed_corpus.zip $SRC/go/src/archive/tar/testdata/*.tar

cd $SRC/instrumentation
go run main.go --target_dir=$SRC/go/src/archive/tar --check_io_length=true

cp $SRC/h2c_fuzzer.go $SRC/net/http2/h2c/
cd $SRC/net/http2/h2c
cd $SRC/instrumentation && go run main.go --target_dir=$SRC/net --check_io_length=true && cd -
go mod tidy -e -go=1.16 && go mod tidy -e -go=1.17
compile_go_fuzzer . FuzzH2c fuzz_x_h2c
mv $SRC/fuzz_x_h2c.options $OUT/

cp $SRC/openpgp_fuzzer.go $SRC/crypto/openpgp/packet
cd $SRC/crypto/openpgp/packet
cd $SRC/instrumentation && go run main.go --target_dir=$SRC/crypto --check_io_length=true && cd -
go mod tidy
compile_go_fuzzer . FuzzOpenpgpRead fuzz_openpgp_read

cd $SRC/image/webp
cp $SRC/webp_fuzzer.go ./
compile_go_fuzzer . FuzzWebpDecode fuzz_webp_decode
zip $OUT/fuzz_webp_decode_seed_corpus.zip $SRC/image/testdata/*.webp

cd $SRC/image/tiff
cp $SRC/tiff_fuzzer.go ./
compile_go_fuzzer . FuzzTiffDecode fuzz_tiff_decode
cp $SRC/fuzz_tiff_decode.options $OUT/
zip $OUT/fuzz_tiff_decode_seed_corpus.zip $SRC/image/testdata/*.tiff

cd $SRC/go/src/archive/tar
cp $SRC/fuzz_tar_reader.go ./
rm ./*_test.go

#compile_go_fuzzer tarPackage FuzzTarReader fuzz_tar_reader
#mv $SRC/fuzz_tar_reader.options $OUT/
#zip $OUT/fuzz_tar_reader_seed_corpus.zip $SRC/go/src/archive/tar/testdata/*.tar

#cd $SRC/go/src/archive/zip
#go mod init zipPackage
#go mod tidy
#find . -name "*_test.go" ! -name 'fuzz_test.go' -type f -exec rm -f {} +
#go get github.com/AdamKorcz/go-118-fuzz-build/testingtypes
#go get github.com/AdamKorcz/go-118-fuzz-build/utils
#compile_native_go_fuzzer zipPackage FuzzReader fuzz_std_lib_zip_reader
#zip $OUT/fuzz_std_lib_zip_reader_seed_corpus.zip $SRC/go/src/archive/zip/testdata/*.zip

cd $SRC/go/src/internal/saferio
go mod init saferioPackage
go mod tidy

cd $SRC/go/src/debug/elf
go mod init elfPackage
go mod tidy
go mod edit -replace internal/saferio=../../internal/saferio
go get internal/saferio
cp $SRC/elf_fuzzer.go ./
rm ./*_test.go
compile_go_fuzzer elfPackage FuzzElfOpen fuzz_elf_open
zip $OUT/fuzz_elf_open_seed_corpus.zip ./testdata/*

cd $SRC/go/src/image/png
go mod init pngPackage
go get github.com/AdamKorcz/go-118-fuzz-build/testing
compile_native_go_fuzzer pngPackage FuzzDecode fuzz_png_decode
zip $OUT/fuzz_png_decode_seed_corpus.zip ./testdata/*.png

cd $SRC/go/src/image/gif
go mod init gifPackage
go get github.com/AdamKorcz/go-118-fuzz-build/testing
compile_native_go_fuzzer gifPackage FuzzDecode fuzz_gif_decode
zip $OUT/fuzz_gif_decode_seed_corpus.zip $SRC/go/src/image/testdata/*.gif

cd $SRC/go/src/compress/gzip
go mod init gzipPackage
go mod tidy
find . -name "*_test.go" ! -name 'fuzz_test.go' -type f -exec rm -f {} +
go get github.com/AdamKorcz/go-118-fuzz-build/testing
compile_native_go_fuzzer gzipPackage FuzzReader fuzz_std_lib_gzip_reader
zip $OUT/fuzz_std_lib_gzip_reader_seed_corpus.zip $SRC/go/src/compress/gzip/testdata/*

cd $SRC/go/src/html
go mod init htmlPackage
go mod tidy
go get github.com/AdamKorcz/go-118-fuzz-build/testing
compile_go_fuzzer htmlPackage Fuzz fuzz_html_escape_unescape

# golangs build from source currently breaks.
exit 0

# Install latest Go from master branch and build fuzzers again
cd $SRC
rm -r go
rm -r golang
git clone --depth 1 https://github.com/golang/go
git clone --depth 1 https://github.com/dvyukov/go-fuzz-corpus $SRC/golang
cd $SRC/go/src
./all.bash
ls /src/go/bin
export GOROOT="/src/go"
export PATH=/src/go/bin:$PATH

# build fuzzers
setup_golang_fuzzers
compile_fuzzers "_latest_master"

# options files
cp $SRC/glob_fuzzer.options $OUT/
cp $SRC/glob_fuzzer.options $OUT/glob_fuzzer_latest_master.options

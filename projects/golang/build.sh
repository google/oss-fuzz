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

# These two dependencies cause build issues and are not used by oss-fuzz:
rm -r sqlparser
rm -r parser

mkdir math && cp $SRC/math_big_fuzzer.go ./math/

cd $SRC/text
cp $SRC/unicode_fuzzer.go ./encoding/unicode/
find . -name "*_test.go" ! -name 'fuzz_test.go' -type f -exec rm -f {} +
compile_go_fuzzer golang.org/x/text/encoding/unicode FuzzUnicodeTransform fuzz_unicode_transform

cd $SRC/golang
mkdir text && cp $SRC/text_fuzzer.go ./text/
cp $SRC/language_fuzzer.go ./text/

mkdir -p crypto/x509
cp $SRC/x509_fuzzer.go ./crypto/x509/

mkdir -p crypto/ecdsa
cp $SRC/ecdsa_fuzzer.go ./crypto/ecdsa/

mkdir -p crypto/aes
cp $SRC/aes_fuzzer.go ./crypto/aes/

go mod init "github.com/dvyukov/go-fuzz-corpus"
export FUZZ_ROOT="github.com/dvyukov/go-fuzz-corpus"
compile_go_fuzzer $FUZZ_ROOT/crypto/x509 FuzzParseCert fuzz_parse_cert
zip $OUT/fuzz_parse_cert_seed_corpus.zip $SRC/go/src/crypto/x509/testdata/*
compile_go_fuzzer $FUZZ_ROOT/crypto/x509 FuzzPemDecrypt fuzz_pem_decrypt
zip $OUT/fuzz_pem_decrypt_seed_corpus.zip $SRC/go/src/crypto/x509/testdata/*
compile_go_fuzzer $FUZZ_ROOT/crypto/aes FuzzAesCipherDecrypt fuzz_aes_cipher_decrypt
compile_go_fuzzer $FUZZ_ROOT/crypto/aes FuzzAesCipherEncrypt fuzz_aes_cipher_encrypt
compile_go_fuzzer $FUZZ_ROOT/crypto/ecdsa FuzzEcdsaSign FuzzEcdsaSign
compile_go_fuzzer $FUZZ_ROOT/text FuzzAcceptLanguage accept_language_fuzzer
compile_go_fuzzer $FUZZ_ROOT/text FuzzMultipleParsers fuzz_multiple_parsers
compile_go_fuzzer $FUZZ_ROOT/text FuzzCurrency currency_fuzzer
compile_go_fuzzer $FUZZ_ROOT/math FuzzBigIntCmp1 big_cmp_fuzzer1
compile_go_fuzzer $FUZZ_ROOT/math FuzzBigIntCmp2 big_cmp_fuzzer2
compile_go_fuzzer $FUZZ_ROOT/math FuzzRatSetString big_rat_fuzzer
compile_go_fuzzer $FUZZ_ROOT/math FuzzFloat64SpecialCases fuzz_float64_special_cases
compile_go_fuzzer $FUZZ_ROOT/asn1 Fuzz asn_fuzzer
compile_go_fuzzer $FUZZ_ROOT/csv Fuzz csv_fuzzer
compile_go_fuzzer $FUZZ_ROOT/elliptic Fuzz elliptic_fuzzer
compile_go_fuzzer $FUZZ_ROOT/flate Fuzz flate_fuzzer
compile_go_fuzzer $FUZZ_ROOT/fmt Fuzz fmt_fuzzer
compile_go_fuzzer $FUZZ_ROOT/gzip Fuzz gzip_fuzzer
compile_go_fuzzer $FUZZ_ROOT/httpreq Fuzz httpreq_fuzzer
compile_go_fuzzer $FUZZ_ROOT/jpeg Fuzz jpeg_fuzzer
compile_go_fuzzer $FUZZ_ROOT/json Fuzz json_fuzzer
compile_go_fuzzer $FUZZ_ROOT/lzw Fuzz lzw_fuzzer
compile_go_fuzzer $FUZZ_ROOT/mime Fuzz mime_fuzzer
compile_go_fuzzer $FUZZ_ROOT/multipart Fuzz multipart_fuzzer
compile_go_fuzzer $FUZZ_ROOT/png Fuzz png_fuzzer
compile_go_fuzzer $FUZZ_ROOT/tar Fuzz tar_fuzzer
compile_go_fuzzer $FUZZ_ROOT/time Fuzz time_fuzzer
compile_go_fuzzer $FUZZ_ROOT/xml Fuzz xml_fuzzer
compile_go_fuzzer $FUZZ_ROOT/zip Fuzz zip_fuzzer
compile_go_fuzzer $FUZZ_ROOT/zlib Fuzz zlib_fuzzer

cd $SRC/go/src/regexp
cp $SRC/regexp_fuzzer.go ./
go mod init regexpPackage
go mod tidy
find . -name "*_test.go" ! -name 'fuzz_test.go' -type f -exec rm -f {} +
compile_go_fuzzer regexpPackage FuzzCompile fuzz_regexp_compile
compile_go_fuzzer regexpPackage FuzzCompilePOSIX fuzz_compile_posix
compile_go_fuzzer regexpPackage FuzzReplaceAll fuzz_replace_all
compile_go_fuzzer regexpPackage FuzzFindMatchApis fuzz_find_match_apis

cd $SRC/go/src/archive/tar
go mod init tarPackage
go mod tidy
find . -name "*_test.go" ! -name 'fuzz_test.go' -type f -exec rm -f {} +
go get github.com/AdamKorcz/go-118-fuzz-build/testingtypes
go get github.com/AdamKorcz/go-118-fuzz-build/utils
compile_native_go_fuzzer tarPackage FuzzReader fuzz_std_lib_tar_reader

cd $SRC/instrumentation
go run main.go $SRC/go/src/archive/tar

cp $SRC/h2c_fuzzer.go $SRC/net/http2/h2c/
cd $SRC/net/http2/h2c
cd $SRC/instrumentation && go run main.go $SRC/net && cd -
go mod tidy -e -go=1.16 && go mod tidy -e -go=1.17
compile_go_fuzzer . FuzzH2c fuzz_h2c
mv $SRC/fuzz_h2c.options $OUT/

cp $SRC/openpgp_fuzzer.go $SRC/crypto/openpgp/packet
cd $SRC/crypto/openpgp/packet
cd $SRC/instrumentation && go run main.go $SRC/crypto && cd -
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

cd $SRC/go/src/archive/tar
cp $SRC/fuzz_tar_reader.go ./
rm ./*_test.go

compile_go_fuzzer tarPackage FuzzTarReader fuzz_tar_reader
mv $SRC/fuzz_tar_reader.options $OUT/ 

cd $SRC/go/src/archive/zip
go mod init zipPackage
go mod tidy
find . -name "*_test.go" ! -name 'fuzz_test.go' -type f -exec rm -f {} +
go get github.com/AdamKorcz/go-118-fuzz-build/testingtypes
go get github.com/AdamKorcz/go-118-fuzz-build/utils
compile_native_go_fuzzer zipPackage FuzzReader fuzz_std_lib_zip_reader

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
go get github.com/AdamKorcz/go-118-fuzz-build/testingtypes
go get github.com/AdamKorcz/go-118-fuzz-build/utils
compile_native_go_fuzzer pngPackage FuzzDecode fuzz_png_decode
zip $OUT/fuzz_png_decode_seed_corpus.zip ./testdata/*.png

cd $SRC/go/src/image/gif
go mod init gifPackage
go get github.com/AdamKorcz/go-118-fuzz-build/testingtypes
go get github.com/AdamKorcz/go-118-fuzz-build/utils
compile_native_go_fuzzer gifPackage FuzzDecode fuzz_gif_decode
zip $OUT/fuzz_gif_decode_seed_corpus.zip $SRC/go/src/image/testdata/*.gif

cd $SRC/go/src/compress/gzip
go mod init gzipPackage
go mod tidy
find . -name "*_test.go" ! -name 'fuzz_test.go' -type f -exec rm -f {} +
go get github.com/AdamKorcz/go-118-fuzz-build/testingtypes
go get github.com/AdamKorcz/go-118-fuzz-build/utils
compile_native_go_fuzzer gzipPackage FuzzReader fuzz_std_lib_gzip_reader

cd $SRC/go/src/html
go mod init htmlPackage
go mod tidy
go get github.com/AdamKorcz/go-118-fuzz-build/testingtypes
go get github.com/AdamKorcz/go-118-fuzz-build/utils
compile_go_fuzzer htmlPackage Fuzz fuzz_html_escape_unescape

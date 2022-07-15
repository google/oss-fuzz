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

git clone https://github.com/golang/text $GOPATH/src/golang.org/x/text
mkdir text && cp $SRC/text_fuzzer.go ./text/

go mod init "github.com/dvyukov/go-fuzz-corpus"
export FUZZ_ROOT="github.com/dvyukov/go-fuzz-corpus"
compile_go_fuzzer $FUZZ_ROOT/text FuzzAcceptLanguage accept_language_fuzzer
compile_go_fuzzer $FUZZ_ROOT/text FuzzCurrency currency_fuzzer
compile_go_fuzzer $FUZZ_ROOT/math FuzzBigIntCmp1 big_cmp_fuzzer1
compile_go_fuzzer $FUZZ_ROOT/math FuzzBigIntCmp2 big_cmp_fuzzer2
compile_go_fuzzer $FUZZ_ROOT/math FuzzRatSetString big_rat_fuzzer
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

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

function compile_fuzzer {
  fuzzer=$(basename $1)

  compile_go_fuzzer "github.com/dvyukov/go-fuzz-corpus/$fuzzer" Fuzz $fuzzer

  # Pack the seed corpus
  zip -r $OUT/fuzzer-${fuzzer}_seed_corpus.zip \
      $GOPATH/src/github.com/dvyukov/go-fuzz-corpus/$fuzzer/corpus
}

export -f compile_fuzzer

# Use this to attempt to compile all
#find $SRC/go-fuzz-corpus -mindepth 1 -maxdepth 1 -type d -exec bash -c 'compile_fuzzer "$@"' bash {} \;

compile_fuzzer asn1
#compile_fuzzer bzip2
compile_fuzzer csv
compile_fuzzer elliptic
compile_fuzzer flate
compile_fuzzer fmt
#compile_fuzzer gif
compile_fuzzer gzip
compile_fuzzer httpreq
compile_fuzzer httpresp
compile_fuzzer jpeg
compile_fuzzer json
compile_fuzzer lzw
compile_fuzzer mime
compile_fuzzer multipart
compile_fuzzer png
compile_fuzzer tar
compile_fuzzer time
#compile_fuzzer url
compile_fuzzer xml
compile_fuzzer zip
compile_fuzzer zlib


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

pip3 install .
mkdir -p corpus_temp
cd corpus_temp
# Download diverse PDFs (Encrypted, Forms, Images, Text)
curl -sLO https://raw.githubusercontent.com/mozilla/pdf.js/master/test/pdfs/tracemonkey.pdf
curl -sLO https://raw.githubusercontent.com/mozilla/pdf.js/master/test/pdfs/bug1056586.pdf
curl -sLO https://raw.githubusercontent.com/mozilla/pdf.js/master/test/pdfs/xfa_form_calc_check.pdf

zip -q $OUT/pypdf_fuzzer_seed_corpus.zip *.pdf
cd ..
rm -rf corpus_temp
for fuzzer in $(find $SRC -name '*_fuzzer.py'); do
  compile_python_fuzzer $fuzzer
done
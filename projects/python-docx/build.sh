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

# Install the library and its dependencies (like lxml)
pip3 install .

mkdir -p corpus_temp
python3 -c '
import docx
doc = docx.Document()
doc.add_paragraph("OSS-Fuzz Seed Document")
doc.add_table(rows=2, cols=2)
doc.save("corpus_temp/seed.docx")
'

# Zip the corpus for OSS-Fuzz
zip -q $OUT/docx_fuzzer_seed_corpus.zip corpus_temp/*
rm -rf corpus_temp

# Compile the Python fuzzer
for fuzzer in $(find $SRC -name '*_fuzzer.py'); do
  compile_python_fuzzer $fuzzer
done
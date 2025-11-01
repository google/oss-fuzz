#!/bin/bash -eu
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
#
################################################################################

# Build and install project (using current CFLAGS, CXXFLAGS).
python3 -m pip install .

# Build fuzzers in $OUT.
for fuzzer in $(find $SRC -name 'fuzz_*.py'); do
  compile_python_fuzzer $fuzzer
done

# Create shared seed corpus
find tests/examplefiles/ -type f | zip -@ -q $OUT/fuzz_lexers_seed_corpus.zip
cp $OUT/fuzz_lexers_seed_corpus.zip $OUT/fuzz_guesser_seed_corpus.zip

# Create shared dictionary
cat fuzzing/dictionaries/aff.dict \
    fuzzing/dictionaries/bash.dict \
    fuzzing/dictionaries/creole.dict \
    fuzzing/dictionaries/css.dict \
    fuzzing/dictionaries/graphviz.dict \
    fuzzing/dictionaries/fbs.dict \
    fuzzing/dictionaries/html.dict \
    fuzzing/dictionaries/jinja2.dict \
    fuzzing/dictionaries/js.dict \
    fuzzing/dictionaries/json.dict \
    fuzzing/dictionaries/lua.dict \
    fuzzing/dictionaries/markdown.dict \
    fuzzing/dictionaries/mathml.dict \
    fuzzing/dictionaries/pdf.dict \
    fuzzing/dictionaries/protobuf.dict \
    fuzzing/dictionaries/ps.dict \
    fuzzing/dictionaries/regexp.dict \
    fuzzing/dictionaries/rst.dict \
    fuzzing/dictionaries/sql.dict \
    fuzzing/dictionaries/svg.dict \
    fuzzing/dictionaries/tex.dict \
    fuzzing/dictionaries/toml.dict \
    fuzzing/dictionaries/utf8.dict \
    fuzzing/dictionaries/vcf.dict \
    fuzzing/dictionaries/wkt.dict \
    fuzzing/dictionaries/x86.dict \
    fuzzing/dictionaries/xml.dict \
    fuzzing/dictionaries/xpath.dict \
    fuzzing/dictionaries/xslt.dict \
    fuzzing/dictionaries/yaml.dict \
    fuzzing/dictionaries/yara.dict \
> "$OUT/fuzz_lexers.dict"

cp "$OUT/fuzz_lexers.dict" "$OUT/fuzz_guesser.dict"

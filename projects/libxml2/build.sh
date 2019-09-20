#!/bin/bash -eu
#
# Copyright 2016 Google Inc.
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

./autogen.sh
./configure --with-http=no
make -j$(nproc) clean
make -j$(nproc) all

# create_seed_corpus name extension
function create_seed_corpus() {
    # Sub-directories of libxml2 to look for seed inputs
    local xml_test_dirs=(./doc ./test ./test/XPath/tests ./result/XPath/tests)
    # Wildcard corpus is used for fuzzers that do not
    # process a file of a known extension.
    if [[ $2 == "wildcard" ]]; then
        find ${xml_test_dirs[@]} -type f | xargs zip $OUT/$1.zip;
    else
        find ${xml_test_dirs[@]} -type f -name "*.$2" | xargs zip $OUT/$1.zip;
    fi
}

function create_seed_corpus_for_all_known_extensions()
{
    local extensions=(xml html xsd rng wildcard)
    for ext in ${extensions[@]}; do
        create_seed_corpus ${ext}_seed_corpus ${ext}
    done
}

create_seed_corpus_for_all_known_extensions

ADD_FUZZERS_DIR=libxml2_fuzzers

for fuzzer in libxml2_xml_read_memory_fuzzer libxml2_xml_reader_for_file_fuzzer \
    $ADD_FUZZERS_DIR/libxml2_regexp_fuzzer \
    $ADD_FUZZERS_DIR/libxml2_html_fuzzer \
    $ADD_FUZZERS_DIR/libxml2_html_pushparse_fuzzer \
    $ADD_FUZZERS_DIR/libxml2_xml_pushparse_fuzzer \
    $ADD_FUZZERS_DIR/libxml2_relax_fuzzer \
    $ADD_FUZZERS_DIR/libxml2_uri_fuzzer \
    $ADD_FUZZERS_DIR/libxml2_schema_fuzzer \
    $ADD_FUZZERS_DIR/libxml2_xpath_fuzzer \
    $ADD_FUZZERS_DIR/libxml2_schema_validate_fuzzer; do
  fuzzer_name=$(basename $fuzzer)
  $CXX $CXXFLAGS -std=c++11 -Iinclude/ \
      $SRC/$fuzzer.cc -o $OUT/${fuzzer_name} \
      $LIB_FUZZING_ENGINE .libs/libxml2.a

  if [[ $fuzzer == *"libxml2_xml"* ]]; then
	  cp $SRC/xml.dict $OUT/${fuzzer_name}.dict
      cp $OUT/xml_seed_corpus.zip $OUT/${fuzzer_name}_seed_corpus.zip
  elif [[ $fuzzer == *"libxml2_html"* ]]; then
	  cp $SRC/html_tags.dict $OUT/${fuzzer_name}.dict
	  cp $OUT/html_seed_corpus.zip $OUT/${fuzzer_name}_seed_corpus.zip
  elif [[ $fuzzer == *"libxml2_schema"* ]]; then
	  cp $OUT/xsd_seed_corpus.zip $OUT/${fuzzer_name}_seed_corpus.zip
  elif [[ $fuzzer == *"libxml2_relax"* ]]; then
	  cp $OUT/rng_seed_corpus.zip $OUT/${fuzzer_name}_seed_corpus.zip
  else
      cp $OUT/wildcard_seed_corpus.zip $OUT/${fuzzer_name}_seed_corpus.zip
  fi
done

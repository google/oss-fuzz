# Copyright 2018 Google Inc.
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

FROM gcr.io/oss-fuzz-base/base-builder
RUN apt-get update && apt-get install -y wget

# Get Wuffs' first-party code.

RUN git clone --depth 1 https://github.com/google/wuffs.git

# Get third-party test corpora.

RUN git clone --depth 1 https://github.com/nst/JSONTestSuite.git

RUN wget -O bmpsuite.zip https://entropymine.com/jason/bmpsuite/releases/bmpsuite-2.6.zip
RUN mkdir bmpsuite_corpus
RUN unzip -j bmpsuite.zip -d bmpsuite_corpus
RUN rm bmpsuite.zip

RUN mkdir pngsuite_corpus && \
    git clone --depth=1 https://github.com/MozillaSecurity/fuzzdata && \
    cp ./fuzzdata/samples/png/common/*.png ./pngsuite_corpus

RUN wget -O rapidjson.zip "https://github.com/guidovranken/rapidjson-fuzzers/blob/master/fuzzer_seed_corpus.zip?raw=true"
RUN mkdir rapidjson_corpus
RUN unzip -j rapidjson.zip -d rapidjson_corpus
RUN rm rapidjson.zip

RUN git clone --depth 1 https://github.com/minio/simdjson-fuzz
RUN mv simdjson-fuzz/corpus/corpus simdjson_corpus
RUN rm -rf simdjson-fuzz

# Finish.

WORKDIR wuffs
COPY build.sh $SRC/

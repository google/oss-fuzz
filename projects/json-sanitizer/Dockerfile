# Copyright 2021 Google LLC
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

FROM gcr.io/oss-fuzz-base/base-builder-jvm

RUN apt-get update && apt-get install -y maven

RUN git clone --depth 1 https://github.com/google/fuzzing
RUN cat fuzzing/dictionaries/json.dict \
        fuzzing/dictionaries/html.dict \
        fuzzing/dictionaries/xml.dict \
      > $SRC/DenylistFuzzer.dict
RUN cp fuzzing/dictionaries/json.dict $SRC/IdempotenceFuzzer.dict
RUN cp fuzzing/dictionaries/json.dict $SRC/ValidJsonFuzzer.dict

RUN git clone --depth 1 https://github.com/dvyukov/go-fuzz-corpus && \
    zip -q $SRC/DenylistFuzzer_seed_corpus.zip go-fuzz-corpus/json/corpus/* && \
    zip -q $SRC/IdempotenceFuzzer_seed_corpus.zip go-fuzz-corpus/json/corpus/* && \
    zip -q $SRC/ValidJsonFuzzer_seed_corpus.zip go-fuzz-corpus/json/corpus/*

RUN git clone --depth 1 https://github.com/OWASP/json-sanitizer
COPY build.sh $SRC/

COPY DenylistFuzzer.java IdempotenceFuzzer.java ValidJsonFuzzer.java $SRC/

WORKDIR $SRC/json-sanitizer

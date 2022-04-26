# Copyright 2022 Google LLC
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

RUN curl -L https://downloads.apache.org/maven/maven-3/3.6.3/binaries/apache-maven-3.6.3-bin.zip -o maven.zip && \
unzip maven.zip -d $SRC/maven && \
rm -rf maven.zip

RUN git clone --depth 1 https://github.com/google/fuzzing
RUN cat fuzzing/dictionaries/json.dict \
    fuzzing/dictionaries/xml.dict \
    > $SRC/StringEscapeUtilsFuzzer.dict

RUN mv fuzzing/dictionaries/html.dict $SRC/EscapeHtmlFuzzer.dict

RUN git clone --depth 1 https://github.com/dvyukov/go-fuzz-corpus && \
    zip -q $SRC/EscapeHtmlFuzzer_seed_corpus.zip go-fuzz-corpus/htmltemplate/corpus/* && \
    zip -q $SRC/StringEscapeUtilsFuzzer_seed_corpus.zip go-fuzz-corpus/json/corpus/* go-fuzz-corpus/csv/corpus/*

ENV MVN $SRC/maven/apache-maven-3.6.3/bin/mvn

RUN git clone --depth 1 https://github.com/apache/commons-lang commons-lang

COPY build.sh $SRC/
COPY *Fuzzer.java $SRC/
WORKDIR $SRC/commons-lang
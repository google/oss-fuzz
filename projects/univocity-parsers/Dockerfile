# Copyright 2023 Google LLC
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

RUN curl -L https://archive.apache.org/dist/maven/maven-3/3.6.3/binaries/apache-maven-3.6.3-bin.zip -o maven.zip && \
    unzip maven.zip -d $SRC/maven && \
    rm -rf maven.zip

ENV MVN $SRC/maven/apache-maven-3.6.3/bin/mvn

RUN git clone --depth 1 https://github.com/google/fuzzing && \
    cp fuzzing/dictionaries/csv.dict $SRC/CsvParserFuzzer.dict && \
    cp fuzzing/dictionaries/csv.dict $SRC/TsvParserFuzzer.dict && \
    rm -rf fuzzing

RUN git clone --depth 1 https://github.com/dvyukov/go-fuzz-corpus && \
    zip -j $SRC/CsvParserFuzzer_seed_corpus.zip go-fuzz-corpus/csv/corpus/* && \
    zip -j $SRC/TsvParserFuzzer_seed_corpus.zip go-fuzz-corpus/csv/corpus/* && \
    rm -rf go-fuzz-corpus

# if not set python infra helper cannot be used for local testing

COPY project-parent $SRC/project-parent/

RUN rm -rf $SRC/project-parent/univocity-parsers
RUN apt update && apt install -y openjdk-11-jdk
RUN git clone --depth 1 https://github.com/univocity/univocity-parsers/ $SRC/project-parent/univocity-parsers

COPY build.sh $SRC/
WORKDIR $SRC/
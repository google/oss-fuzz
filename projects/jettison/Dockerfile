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

RUN curl -L https://dlcdn.apache.org/maven/maven-3/3.8.5/binaries/apache-maven-3.8.5-bin.zip -o maven.zip && \
    unzip maven.zip -d $SRC/maven && \
    rm -rf maven.zip

ENV MVN $SRC/maven/apache-maven-3.8.5/bin/mvn

RUN git clone --depth 1 https://github.com/google/fuzzing && \
    mv fuzzing/dictionaries/json.dict $SRC/JsonFuzzer.dict && \
    rm -rf fuzzing

RUN git clone --depth 1 https://github.com/dvyukov/go-fuzz-corpus && \
    zip -j $SRC/JsonFuzzer_seed_corpus.zip go-fuzz-corpus/json/corpus/* && \
    rm -rf go-fuzz-corpus

RUN git clone --depth 1 https://github.com/jettison-json/jettison.git jettison

COPY build.sh $SRC/
COPY JsonFuzzer.java $SRC/
WORKDIR $SRC/jettison

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
    cp fuzzing/dictionaries/json.dict $SRC/JsonArrayFuzzer.dict && \
    cp fuzzing/dictionaries/json.dict $SRC/JsonObjectFuzzer.dict && \
    cp fuzzing/dictionaries/js.dict $SRC/JsParserFuzzer.dict && \
    rm -rf fuzzing

RUN git clone --depth 1 https://github.com/dvyukov/go-fuzz-corpus && \
    zip -j $SRC/JsonArrayFuzzer_seed_corpus.zip go-fuzz-corpus/json/corpus/* && \
    zip -j $SRC/JsonObjectFuzzer_seed_corpus.zip go-fuzz-corpus/json/corpus/* && \
    rm -rf go-fuzz-corpus

# if not set python infra helper cannot be used for local testing

COPY project-parent $SRC/project-parent/

RUN rm -rf $SRC/project-parent/gwt
RUN rm -rf $SRC/project-parent/tools
RUN apt update && apt install -y openjdk-8-jdk
RUN git clone --depth 1 https://github.com/gwtproject/gwt/ $SRC/project-parent/gwt
RUN git clone --depth 1 https://github.com/gwtproject/tools/ $SRC/project-parent/tools

COPY build.sh $SRC/
COPY pom.xml $SRC/project-parent/gwt
WORKDIR $SRC/
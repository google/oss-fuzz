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

ARG MAVEN_VERSION=3.9.11

RUN curl -L https://archive.apache.org/dist/maven/maven-3/$MAVEN_VERSION/binaries/apache-maven-$MAVEN_VERSION-bin.zip -o maven.zip && \
    unzip maven.zip -d $SRC/maven && \
    rm -rf maven.zip

ENV MVN $SRC/maven/apache-maven-$MAVEN_VERSION/bin/mvn

RUN git clone --depth 1 https://github.com/google/fuzzing && \
    cat fuzzing/dictionaries/html.dict \
        fuzzing/dictionaries/svg.dict \
        fuzzing/dictionaries/mathml.dict \
        fuzzing/dictionaries/css.dict \
        fuzzing/dictionaries/xml.dict \
        fuzzing/dictionaries/xpath.dict \
    fuzzing/dictionaries/http.dict >> $SRC/combo.dict && \
    rm -rf fuzzing

RUN git clone --depth 1 https://github.com/dvyukov/go-fuzz-corpus && \
    zip -j $SRC/XmlFuzzer_seed_corpus.zip go-fuzz-corpus/xml/corpus/* && \
    rm -rf go-fuzz-corpus

RUN git clone --depth 1 https://github.com/jhy/jsoup/

# re2j is an optional/test dependency, but we want it available on the fuzzed classpath
RUN curl -L https://github.com/google/re2j/releases/download/re2j-1.8/re2j-1.8.jar -o $SRC/re2j.jar

COPY build.sh *.java *.options $SRC/
WORKDIR $SRC/jsoup

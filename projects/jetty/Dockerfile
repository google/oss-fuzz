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

RUN curl -L https://dlcdn.apache.org/maven/maven-3/3.8.6/binaries/apache-maven-3.8.6-bin.zip -o maven.zip && \
    unzip maven.zip -d $SRC/maven && \
    rm -rf maven.zip

ENV MVN $SRC/maven/apache-maven-3.8.6/bin/mvn

RUN git clone --depth 1 https://github.com/google/fuzzing
RUN cat fuzzing/dictionaries/http.dict \
      > $SRC/ServerHandlersFuzzer.dict

RUN cat fuzzing/dictionaries/url.dict \
      > $SRC/ServerHandlersFuzzer.dict

RUN git clone --depth 1 https://github.com/dvyukov/go-fuzz-corpus && \
    zip -q $SRC/ServerHandlersFuzzer_seed_corpus.zip go-fuzz-corpus/httpreq/corpus/*


RUN git clone --depth 1 https://github.com/eclipse/jetty.project.git

COPY build.sh $SRC/
COPY *Fuzzer.java $SRC/
COPY pom.patch $SRC/jetty.project
WORKDIR $SRC/jetty.project
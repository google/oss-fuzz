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

RUN curl -L https://archive.apache.org/dist/maven/maven-3/3.8.7/binaries/apache-maven-3.8.7-bin.zip -o maven.zip && \
    unzip maven.zip -d $SRC/maven && \
    rm -rf maven.zip

ENV MVN $SRC/maven/apache-maven-3.8.7/bin/mvn

RUN git clone --depth 1 https://github.com/ebourg/jsign.git

RUN zip -j $SRC/AuthenticodeExeSignerFuzzer_seed_corpus.zip jsign/jsign-core/src/test/resources/*.exe && \
    zip -j $SRC/AuthenticodeMsiSignerFuzzer_seed_corpus.zip jsign/jsign-core/src/test/resources/*.msi && \
    zip -j $SRC/AuthenticodeCabSignerFuzzer_seed_corpus.zip jsign/jsign-core/src/test/resources/mscab/*.cab

COPY build.sh $SRC/
COPY *Fuzzer.java $SRC/
WORKDIR $SRC/jsign

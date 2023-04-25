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
    cp fuzzing/dictionaries/xml.dict $SRC/XMLStreamReadersFuzzer.dict && \
    cp fuzzing/dictionaries/xml.dict $SRC/W3CDOMStreamReaderFuzzer.dict && \
    rm -rf fuzzing

RUN git clone --depth 1 https://github.com/dvyukov/go-fuzz-corpus && \
    zip -j $SRC/XMLStreamReadersFuzzer_seed_corpus.zip go-fuzz-corpus/xml/corpus/* && \
    zip -j $SRC/W3CDOMStreamReaderFuzzer_seed_corpus.zip go-fuzz-corpus/xml/corpus/* && \
    rm -rf go-fuzz-corpus

COPY project-parent $SRC/project-parent/

RUN rm -rf $SRC/project-parent/cxf
RUN apt update && apt install -y openjdk-17-jdk
RUN git clone --depth 1 https://github.com/apache/cxf/ $SRC/project-parent/cxf

COPY build.sh $SRC/
WORKDIR $SRC/
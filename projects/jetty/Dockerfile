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

RUN curl -L https://archive.apache.org/dist/maven/maven-3/3.6.3/binaries/apache-maven-3.6.3-bin.zip -o maven.zip && \
    unzip maven.zip -d $SRC/maven && \
    rm -rf maven.zip

ENV MVN $SRC/maven/apache-maven-3.6.3/bin/mvn

RUN git clone --depth 1 https://github.com/google/fuzzing && \
    cp fuzzing/dictionaries/http.dict $SRC/HTTP2CServerFuzzer.dict && \
    mv fuzzing/dictionaries/http.dict $SRC/HttpParserFuzzer.dict && \
    mv fuzzing/dictionaries/xml.dict $SRC/XmlParserFuzzer.dict && \
    rm -rf fuzzing

RUN git clone --depth 1 https://github.com/dvyukov/go-fuzz-corpus && \
    zip -j $SRC/HTTP2CServerFuzzer_seed_corpus.zip go-fuzz-corpus/http2/corpus/* && \
    zip -j $SRC/HttpParserFuzzer_seed_corpus.zip go-fuzz-corpus/httpreq/corpus/* && \
    zip -j $SRC/XmlParserFuzzer_seed_corpus.zip go-fuzz-corpus/xml/corpus/* && \
    rm -rf go-fuzz-corpus

COPY project-parent $SRC/project-parent/

RUN rm -rf $SRC/project-parent/jetty
RUN git clone --depth 1 https://github.com/eclipse/jetty.project $SRC/project-parent/jetty

# required by jetty's asciidoctor-maven-plugin
RUN apt-get update && apt-get -y install fontconfig

COPY build.sh $SRC/
WORKDIR $SRC/
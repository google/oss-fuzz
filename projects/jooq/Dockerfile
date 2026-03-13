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
##########################################################################
FROM gcr.io/oss-fuzz-base/base-builder-jvm

RUN curl -L https://archive.apache.org/dist/maven/maven-3/3.9.2/binaries/apache-maven-3.9.2-bin.zip -o maven.zip && \
    unzip maven.zip -d $SRC/maven && \
    rm -rf maven.zip

RUN curl -L https://download.java.net/java/GA/jdk21.0.2/f2283984656d49d69e91c558476027ac/13/GPL/openjdk-21.0.2_linux-x64_bin.tar.gz -o jdk.tar.gz && \
    tar zxf jdk.tar.gz && \
    rm -rf jdk.tar.gz

RUN curl -L https://github.com/protocolbuffers/protobuf/releases/download/v3.15.8/protoc-3.15.8-linux-x86_64.zip -o protoc.zip && mkdir -p $SRC/protoc && unzip protoc.zip -d $SRC/protoc && rm -rf protoc.zip

ENV MVN $SRC/maven/apache-maven-3.9.2/bin/mvn
ENV JAVA_HOME="$SRC/jdk-21.0.2"
ENV PATH="$JAVA_HOME/bin:$SRC/protoc/bin:$PATH"
RUN git clone --depth 1 https://github.com/jOOQ/jOOQ.git jooq
COPY *.sh *.java $SRC/
WORKDIR $SRC/jooq

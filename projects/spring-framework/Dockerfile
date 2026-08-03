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

# Spring Framework main branch requires Java 25
# Download and install OpenJDK 25 GA
RUN apt update && apt install -y wget && \
    wget -q https://download.java.net/java/GA/jdk25.0.1/2fbf10d8c78e40bd87641c434705079d/8/GPL/openjdk-25.0.1_linux-x64_bin.tar.gz -O /tmp/openjdk25.tar.gz && \
    mkdir -p /usr/lib/jvm && \
    tar -xzf /tmp/openjdk25.tar.gz -C /usr/lib/jvm && \
    mv /usr/lib/jvm/jdk-25.0.1 /usr/lib/jvm/java-25-openjdk-amd64 && \
    rm /tmp/openjdk25.tar.gz && \
    update-alternatives --install /usr/bin/java java /usr/lib/jvm/java-25-openjdk-amd64/bin/java 1 && \
    update-alternatives --install /usr/bin/javac javac /usr/lib/jvm/java-25-openjdk-amd64/bin/javac 1 && \
    update-alternatives --set java /usr/lib/jvm/java-25-openjdk-amd64/bin/java && \
    update-alternatives --set javac /usr/lib/jvm/java-25-openjdk-amd64/bin/javac

ENV JAVA_HOME=/usr/lib/jvm/java-25-openjdk-amd64

RUN git clone --depth 1 https://github.com/spring-projects/spring-framework

COPY . $SRC/

RUN  cd spring-framework && (for i in ${SRC}/add-shadow-*.diff; do tr -d '\015' < $i | git apply -v; done )

RUN git clone --depth 1 https://github.com/google/fuzzing && \
    mv fuzzing/dictionaries/xml.dict $SRC/spring-context/XmlApplicationContextFuzzer.dict && \
    rm -rf fuzzing

RUN git clone --depth 1 https://github.com/dvyukov/go-fuzz-corpus && \
    zip -j $SRC/spring-context/XmlApplicationContextFuzzer_seed_corpus.zip go-fuzz-corpus/xml/corpus/* && \
    rm -rf go-fuzz-corpus

WORKDIR $SRC/spring-framework
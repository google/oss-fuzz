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

RUN curl -L https://archive.apache.org/dist/maven/maven-3/3.9.9/binaries/apache-maven-3.9.9-bin.zip -o maven.zip && \
    unzip maven.zip -d $SRC/maven && \
    rm -rf maven.zip

ENV MVN $SRC/maven/apache-maven-3.9.9/bin/mvn

# Kryo 6 needs JDK 24+ to build, its classes run on Java 17. Kryo 5 builds with it too.
RUN curl -L https://github.com/adoptium/temurin25-binaries/releases/download/jdk-25.0.4.1%2B1/OpenJDK25U-jdk_x64_linux_hotspot_25.0.4.1_1.tar.gz -o jdk.tar.gz && \
    mkdir -p $SRC/jdk25 && \
    tar -xzf jdk.tar.gz -C $SRC/jdk25 --strip-components=1 && \
    rm -rf jdk.tar.gz

RUN git clone --depth 1 https://github.com/EsotericSoftware/kryo

COPY build.sh $SRC/
COPY DeserializeCollectionsFuzzer.java DeserializeNumbersFuzzer.java DeserializeStringFuzzer.java $SRC/
WORKDIR $SRC/kryo

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
unzip maven.zip -d $SRC/maven-3.6.3 && \
rm -rf maven.zip

ENV MVN $SRC/maven-3.6.3/apache-maven-3.6.3/bin/mvn

RUN wget https://github.com/adoptium/temurin8-binaries/releases/download/jdk8u382-b05/OpenJDK8U-jdk_x64_linux_hotspot_8u382b05.tar.gz && \
  tar xvf OpenJDK8U-jdk_x64_linux_hotspot_8u382b05.tar.gz && \
  rm -rf OpenJDK8U-jdk_x64_linux_hotspot_8u382b05.tar.gz

ENV JAVA_HOME_8 $SRC/jdk8u382-b05

RUN wget https://github.com/adoptium/temurin11-binaries/releases/download/jdk-11.0.20%2B8/OpenJDK11U-jdk_x64_linux_hotspot_11.0.20_8.tar.gz && \
  tar xvf OpenJDK11U-jdk_x64_linux_hotspot_11.0.20_8.tar.gz && \
  rm -rf OpenJDK11U-jdk_x64_linux_hotspot_11.0.20_8.tar.gz

ENV JAVA_HOME_11 $SRC/jdk-11.0.20+8

WORKDIR ${SRC}
#
# clone repository
#
RUN git clone --depth 1 https://github.com/apache/poi.git

ADD pom.xml build.sh ${SRC}/
ADD src/ ${SRC}/src/
WORKDIR ${SRC}/poi
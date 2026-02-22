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

# Newer Maven release are listed at https://archive.apache.org/dist/maven/maven-3/
RUN curl -L https://archive.apache.org/dist/maven/maven-3/3.9.12/binaries/apache-maven-3.9.12-bin.zip -o maven.zip && \
unzip maven.zip -d $SRC/maven-3.9.12 && \
rm -rf maven.zip

ENV MVN $SRC/maven-3.9.12/apache-maven-3.9.12/bin/mvn
ENV TARGET_PACKAGE_PREFIX org.apache.poi.*:org.apache.xmlbeans.*

# Newer JDK releases are listed at https://github.com/adoptium/temurin11-binaries/releases/
RUN curl -L https://github.com/adoptium/temurin11-binaries/releases/download/jdk-11.0.29%2B7/OpenJDK11U-jdk_x64_linux_hotspot_11.0.29_7.tar.gz -o OpenJDK11U-jdk_x64_linux_hotspot_11.0.29_7.tar.gz && \
  tar xvf OpenJDK11U-jdk_x64_linux_hotspot_11.0.29_7.tar.gz && \
  rm -rf OpenJDK11U-jdk_x64_linux_hotspot_11.0.29_7.tar.gz

ENV JAVA_HOME_11 $SRC/jdk-11.0.29+7

WORKDIR ${SRC}
#
# clone repository
#
RUN git clone --depth 1 https://github.com/apache/poi.git

# install packages required for font-handling and other code in java.awt.*
RUN apt-get update && apt-get install -y libxext6 libx11-6 libxrender1 libxtst6 libxi6 libxcb1 libxau6 libxdmcp6 libfreetype6 libpng16-16 \
&& apt-get clean autoclean \
&& apt-get autoremove --yes \
&& rm -rf /var/lib/{apt,dpkg,cache,log}/

# Remove unused code-parts to speed up introspection
# Need to keep some test-code which is used in the poi-integration module
RUN cd ${SRC}/poi && rm `find \
    jenkins \
    osgi \
    poi/src/test/ \
    poi-examples/src/test \
    poi-excelant/src/test \
    poi-ooxml/src/test \
    poi-scratchpad/src/test \
    src \
    \
    -name *.java -a ! -name *DataSamples*.java -a ! -name Biff*.java`

ADD pom.xml build.sh ${SRC}/
ADD src/ ${SRC}/src/
WORKDIR ${SRC}/poi

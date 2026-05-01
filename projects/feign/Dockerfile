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
ENV MVN="$SRC/maven/apache-maven-3.9.2/bin/mvn"
ENV JAVA_HOME="$SRC/jdk-21.0.2"
RUN git clone --depth 1 https://github.com/openfeign/feign feign
COPY *.sh *.java *.xml $SRC/
WORKDIR $SRC/feign
# Ensure the ~/.m2 directory exists and copy toolchains.xml there
RUN mkdir -p ~/.m2 && cp $SRC/toolchains.xml ~/.m2/toolchains.xml
# Use the Maven settings file to resolve dependencies
RUN $MVN --settings $SRC/settings.xml clean package -Dmaven.javadoc.skip=true \
        -DskipTests=true -Dpmd.skip=true -Dencoding=UTF-8 \
        -Dmaven.antrun.skip=true -Dcheckstyle.skip=true -Denforcer.fail=false \
        dependency:copy-dependencies

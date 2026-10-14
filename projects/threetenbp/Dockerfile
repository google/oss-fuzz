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
RUN curl -L https://archive.apache.org/dist/maven/maven-3/3.6.3/binaries/apache-maven-3.6.3-bin.zip \
      -o maven.zip && \
      unzip maven.zip -d $SRC/maven && \
      rm maven.zip
RUN apt-get update && apt-get install -y ca-certificates-java && \
    update-ca-certificates -f
RUN curl -L https://github.com/adoptium/temurin11-binaries/releases/download/jdk-11.0.22%2B7/OpenJDK11U-jdk_x64_linux_hotspot_11.0.22_7.tar.gz \
      -o jdk.tar.gz && \
    JDK_DIR=$(tar -tf jdk.tar.gz | head -1 | cut -d/ -f1) && \
    tar zxf jdk.tar.gz && \
    rm jdk.tar.gz && \
    mv "$JDK_DIR" "$SRC/jdk11" && \
    rm -f "$SRC/jdk11/lib/security/cacerts" && \
    ln -s /etc/ssl/certs/java/cacerts "$SRC/jdk11/lib/security/cacerts"
ENV MVN $SRC/maven/apache-maven-3.6.3/bin/mvn
ENV JAVA_HOME=$SRC/jdk11
ENV PATH="$JAVA_HOME/bin:$PATH"
RUN git clone --depth 1 https://github.com/ThreeTen/threetenbp threetenbp
COPY *.sh *.java $SRC/
WORKDIR $SRC/threetenbp

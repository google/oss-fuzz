# Copyright 2026 Google LLC
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

# SafeRE requires JDK 26 to build from source (see .sdkmanrc and README.md)
# Download and install Eclipse Temurin 26
RUN apt-get update && apt-get install -y maven zip rsync curl && \
    mkdir -p /usr/lib/jvm/java-26-openjdk-amd64 && \
    curl -L https://github.com/adoptium/temurin26-binaries/releases/download/jdk-26.0.2%2B10/OpenJDK26U-jdk_x64_linux_hotspot_26.0.2_10.tar.gz -o /tmp/jdk26.tar.gz && \
    tar -xzf /tmp/jdk26.tar.gz -C /usr/lib/jvm/java-26-openjdk-amd64 --strip-components=1 && \
    rm /tmp/jdk26.tar.gz && \
    update-alternatives --install /usr/bin/java java /usr/lib/jvm/java-26-openjdk-amd64/bin/java 1 && \
    update-alternatives --install /usr/bin/javac javac /usr/lib/jvm/java-26-openjdk-amd64/bin/javac 1 && \
    update-alternatives --set java /usr/lib/jvm/java-26-openjdk-amd64/bin/java && \
    update-alternatives --set javac /usr/lib/jvm/java-26-openjdk-amd64/bin/javac

ENV JAVA_HOME /usr/lib/jvm/java-26-openjdk-amd64
ENV PATH $JAVA_HOME/bin:$PATH

RUN git clone --depth 1 https://github.com/google/fuzzing $SRC/google-fuzzing
RUN git clone --depth 1 https://github.com/eaftan/safere.git $SRC/safere

COPY build.sh $SRC/
WORKDIR $SRC/safere

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

# Download and install JDK 17
RUN apt-get update && apt-get install -y wget apt-transport-https gnupg
RUN wget -qO - https://packages.adoptium.net/artifactory/api/gpg/key/public | gpg --dearmor | tee /etc/apt/trusted.gpg.d/adoptium.gpg > /dev/null \
    && echo "deb https://packages.adoptium.net/artifactory/deb/ focal main" | tee /etc/apt/sources.list.d/adoptium.list \
    && apt-get update && apt-get install -y temurin-17-jdk
# Remove the directory (ensure this is correct and necessary for your application)
RUN rm -rf $SRC/project-parent/jxls
# Set JAVA_HOME. This needs to be adjusted to the path where the JDK is installed.
# Since we're installing temurin-17-jdk, we'll set it directly.
ENV JAVA_HOME /usr/lib/jvm/temurin-17-jdk-amd64
ENV PATH $PATH:$JAVA_HOME/bin

RUN rm -rf $SRC/jxls
RUN git clone --depth 1 https://github.com/jxlsteam/jxls $SRC/jxls

RUN apt-get update && apt-get install -y maven

# Build the project
COPY build.sh $SRC/
COPY *Fuzzer.java $SRC/
COPY *.dict $SRC/
WORKDIR $SRC/jxls

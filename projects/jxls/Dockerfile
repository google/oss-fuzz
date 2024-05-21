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

# Install necessary packages
RUN apt-get update && apt-get install -y wget apt-transport-https gnupg
# Download and install JDK 17 from the official Oracle website
RUN wget -q --no-cookies --no-check-certificate --header "Cookie: oraclelicense=accept-securebackup-cookie" "https://download.oracle.com/otn-pub/java/jdk/17+35/61f34f82bd5b40629948c6f6a52b8fe0/jdk-17_linux-x64_bin.tar.gz" -O /tmp/jdk-17_linux-x64_bin.tar.gz
RUN mkdir -p /usr/lib/jvm && tar -zxf /tmp/jdk-17_linux-x64_bin.tar.gz -C /usr/lib/jvm
RUN update-alternatives --install /usr/bin/java java /usr/lib/jvm/jdk-17/bin/java 100
RUN update-alternatives --install /usr/bin/javac javac /usr/lib/jvm/jdk-17/bin/javac 100
# Clean up
RUN rm /tmp/jdk-17_linux-x64_bin.tar.gz
# Set JAVA_HOME and PATH
ENV JAVA_HOME /usr/lib/jvm/jdk-17
ENV PATH $PATH:$JAVA_HOME/bin


RUN rm -rf $SRC/jxls
RUN git clone --depth 1 https://github.com/jxlsteam/jxls $SRC/jxls

RUN apt-get update && apt-get install -y maven

# Build the project
COPY build.sh $SRC/
COPY *Fuzzer.java $SRC/
COPY *.dict $SRC/
WORKDIR $SRC/jxls

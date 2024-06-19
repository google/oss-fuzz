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
RUN wget -q --no-cookies --no-check-certificate --header "Cookie: oraclelicense=accept-securebackup-cookie" "https://download.oracle.com/java/17/archive/jdk-17.0.10_linux-x64_bin.tar.gz" -O /tmp/jdk-17_linux-x64_bin.tar.gz

# extract JDK installation
RUN mkdir -p /home/user/jdk
RUN tar -zxvf /tmp/jdk-17_linux-x64_bin.tar.gz -C /home/user/jdk

# Debug: List the contents of the user home directory
RUN ls -la /home/user/jdk

# Set the JAVA_HOME and PATH variables correctly
ENV JAVA_HOME /home/user/jdk/jdk-17.0.10
ENV PATH $JAVA_HOME/bin:$PATH

# Debug: Print the JAVA_HOME, and PATH environment variables
RUN echo "JAVA_HOME: $JAVA_HOME"
RUN echo "PATH: $PATH"

# Clean up
RUN rm /tmp/jdk-17_linux-x64_bin.tar.gz

# Confirm Java installation
RUN java -version

# Install Maven
RUN apt-get update && apt-get install -y maven

# Clone project
RUN rm -rf $SRC
RUN echo "Cloning jxls into $SRC"
RUN git clone https://github.com/jxlsteam/jxls $SRC

# Copy fuzzer files
COPY build.sh $SRC/
COPY *Fuzzer.java $SRC/
COPY *.dict $SRC/
WORKDIR $SRC

RUN ls .


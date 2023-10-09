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

RUN curl -L https://download.java.net/openjdk/jdk11.0.0.1/ri/openjdk-11.0.0.1_linux-x64_bin.tar.gz -o jdk.tar.gz && \
    tar zxf jdk.tar.gz && \
    rm -rf jdk.tar.gz

ENV JAVA_HOME="$SRC/jdk-11.0.0.1"
ENV PATH="$JAVA_HOME/bin:$PATH"
RUN git clone --depth 1 https://github.com/quartz-scheduler/quartz quartz
COPY *.sh *.java $SRC/
WORKDIR $SRC/quartz

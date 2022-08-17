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

RUN curl -L https://dlcdn.apache.org//ant/binaries/apache-ant-1.10.12-bin.tar.gz -o ant.tar.gz && \
    mkdir -p $SRC/ant && \
    tar -zxvf ant.tar.gz -C $SRC/ant --strip-components=1 && \
    rm -rf ant.tar.gz

ARG java_home="/out/open-jdk"

RUN apt update && apt install -y default-jdk
ENV JAVA_HOME $java_home
ENV PATH "${java_home}:${PATH}"
ENV JVM_LD_LIBRARY_PATH "$java_home/lib/server"

ENV ANT_HOME=$SRC/ant
ENV ANT $SRC/ant/bin/ant

RUN git clone --depth 1 https://github.com/apache/tomcat

COPY build.sh $SRC/
COPY *Fuzzer.java $SRC/
WORKDIR $SRC/tomcat
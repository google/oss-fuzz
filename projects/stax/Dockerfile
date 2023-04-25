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

#
# install maven configuration, which is also used by gradles's publishToMavenLocal
#
ADD maven-settings.xml ${SRC}/
RUN apt-get install -y xmlstarlet
RUN mkdir -p ~/.m2 && \
	xmlstarlet ed \
		-u "settings/localRepository" -v "${OUT}/m2/repository" \
	< ${SRC}/maven-settings.xml > ~/.m2/settings.xml

#
# install maven and gradle
#
RUN curl -L https://archive.apache.org/dist/maven/maven-3/3.8.7/binaries/apache-maven-3.8.7-bin.zip -o maven.zip && \
	unzip maven.zip -d $SRC/maven-3.8.7 && \
	rm -rf maven.zip

ENV MVN $SRC/maven-3.8.7/apache-maven-3.8.7/bin/mvn

RUN curl -L https://services.gradle.org/distributions/gradle-7.6-bin.zip -o gradle.zip && \
    unzip gradle.zip -d $SRC/gradle && \
    rm -rf gradle.zip

ENV GRADLE $SRC/gradle/gradle-7.6/bin/gradle

ENV LIBRARY_NAME stax
WORKDIR ${SRC}
#
# clone repository
#
RUN git clone https://git.openjdk.org/jdk/ ${SRC}/jdk
#
# Install jdk dependencies. Current master needs JDK 19 or newer, which isn't available
# in ubuntu's repositories yet
#
RUN apt install -y autoconf file libasound2-dev libcups2-dev libfontconfig1-dev \
		libx11-dev libxext-dev libxrender-dev libxrandr-dev libxtst-dev libxt-dev
RUN curl -o ${SRC}/jdk-19_linux-x64_bin.deb https://download.oracle.com/java/19/latest/jdk-19_linux-x64_bin.deb && \
	apt install -y ${SRC}/jdk-19_linux-x64_bin.deb
ENV JAVA_HOME /usr/lib/jvm/jdk-19/
ENV CC gcc
ENV CXX g++
#
# apply fixes
#
#ADD *.patch ${SRC}/
#RUN cd ${SRC}/${LIBRARY_NAME} && (for i in ${SRC}/*.patch; do tr -d '\015' < $i | git apply -v; done )

ADD build.sh build-jdk.sh enable-jdk.sh ${SRC}/
ADD ${LIBRARY_NAME}-fuzzer ${SRC}/${LIBRARY_NAME}-fuzzer/
WORKDIR ${SRC}/${LIBRARY_NAME}

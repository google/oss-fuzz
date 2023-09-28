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

ENV LIBRARY_NAME equinox
WORKDIR ${SRC}
#
# Clone repository. eclipse-equinox has an auxillary repository, which
# also has to be cloned...
#
RUN git clone https://github.com/eclipse-equinox/equinox
RUN git clone https://github.com/eclipse-equinox/equinox.binaries

#
# Multiple JDK versions are required in order to build equinox, and they
# also need to be configured into a maven toolchain for concurrent use.
#
RUN apt update && apt install -y openjdk-8-jdk-headless openjdk-11-jdk-headless openjdk-17-jdk-headless
ENV JAVA_HOME /usr/lib/jvm/java-17-openjdk-amd64
ADD maven-toolchains.xml ${SRC}/ 
RUN mkdir -p ~/.m2 && \
	cp ${SRC}/maven-toolchains.xml ~/.m2/toolchains.xml

ADD build.sh ${SRC}/
ADD ${LIBRARY_NAME}-fuzzer ${SRC}/${LIBRARY_NAME}-fuzzer/
WORKDIR ${SRC}/${LIBRARY_NAME}
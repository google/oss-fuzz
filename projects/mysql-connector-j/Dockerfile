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

RUN curl -L https://dlcdn.apache.org//ant/binaries/apache-ant-1.10.12-bin.zip -o ant.zip && \
    unzip ant.zip -d $SRC/ant && \
    rm -rf ant.zip

ENV ANT $SRC/ant/apache-ant-1.10.12/bin/ant

#
# deploy mysql-server
#
RUN apt-get install -y mysql-server

#
# Source build instructions on
#   https://dev.mysql.com/doc/connector-j/8.0/en/connector-j-installing-source.html
#

WORKDIR ${SRC}
#
# clone repository
#
RUN git clone --branch release/8.0 https://github.com/mysql/mysql-connector-j.git

#
# download and provision dependencies
#
RUN mkdir mysql-connector-j/lib

RUN curl -o mysql-connector-j/lib/junit-jupiter-api-5.8.2.jar https://repo1.maven.org/maven2/org/junit/jupiter/junit-jupiter-api/5.8.2/junit-jupiter-api-5.8.2.jar
RUN curl -o mysql-connector-j/lib/junit-jupiter-engine-5.8.2.jar https://repo1.maven.org/maven2/org/junit/jupiter/junit-jupiter-engine/5.8.2/junit-jupiter-engine-5.8.2.jar
RUN curl -o mysql-connector-j/lib/junit-platform-commons-1.8.2.jar https://repo1.maven.org/maven2/org/junit/platform/junit-platform-commons/1.8.2/junit-platform-commons-1.8.2.jar
RUN curl -o mysql-connector-j/lib/junit-platform-engine-1.8.2.jar https://repo1.maven.org/maven2/org/junit/platform/junit-platform-engine/1.8.2/junit-platform-engine-1.8.2.jar
RUN curl -o mysql-connector-j/lib/junit-platform-launcher-1.8.2.jar https://repo1.maven.org/maven2/org/junit/platform/junit-platform-launcher/1.8.2/junit-platform-launcher-1.8.2.jar                        
RUN curl -o mysql-connector-j/lib/apiguardian-api-1.1.2.jar https://repo1.maven.org/maven2/org/apiguardian/apiguardian-api/1.1.2/apiguardian-api-1.1.2.jar
RUN curl -o mysql-connector-j/lib/opentest4j-1.2.0.jar https://repo1.maven.org/maven2/org/opentest4j/opentest4j/1.2.0/opentest4j-1.2.0.jar
RUN curl -o mysql-connector-j/lib/javassist-3.28.0-GA.jar https://repo1.maven.org/maven2/org/javassist/javassist/3.28.0-GA/javassist-3.28.0-GA.jar
RUN curl -o mysql-connector-j/lib/protobuf-java-3.19.4.jar https://repo1.maven.org/maven2/com/google/protobuf/protobuf-java/3.19.4/protobuf-java-3.19.4.jar
RUN curl -o mysql-connector-j/lib/slf4j-api-1.7.35.jar https://repo1.maven.org/maven2/org/slf4j/slf4j-api/1.7.35/slf4j-api-1.7.35.jar
RUN curl -o mysql-connector-j/lib/hamcrest-2.2.jar https://repo1.maven.org/maven2/org/hamcrest/hamcrest/2.2/hamcrest-2.2.jar
RUN curl -o mysql-connector-j/lib/oci-java-sdk-common-2.14.1.jar https://repo1.maven.org/maven2/com/oracle/oci/sdk/oci-java-sdk-common/2.14.1/oci-java-sdk-common-2.14.1.jar

#
# get rid of 'java version "1.8' version test that fails on 'java version "15'
#
RUN cp mysql-connector-j/build.xml mysql-connector-j/build.xml.orig
RUN cat mysql-connector-j/build.xml.orig | sed '/version \&quot;1.8/d' > mysql-connector-j/build.xml

COPY entrypoint.sh $SRC/entrypoint.sh
RUN  chmod +x $SRC/entrypoint.sh


COPY build.sh $SRC/
COPY *.java $SRC/
WORKDIR $SRC/mysql-connector-j
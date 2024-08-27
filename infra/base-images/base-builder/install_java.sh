#!/bin/bash -eux
# Copyright 2021 Google LLC
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

# Install OpenJDK 17 and trim its size by removing unused components. This enables using Jazzer's mutation framework.
cd /tmp
curl --silent -L -O https://download.java.net/java/GA/jdk17.0.2/dfd4a8d0985749f896bed50d7138ee7f/8/GPL/openjdk-17.0.2_linux-x64_bin.tar.gz && \
mkdir -p $JAVA_HOME
tar -xz --strip-components=1 -f openjdk-17.0.2_linux-x64_bin.tar.gz --directory $JAVA_HOME && \
rm -f openjdk-17.0.2_linux-x64_bin.tar.gz
rm -rf $JAVA_HOME/jmods $JAVA_HOME/lib/src.zip

# Install OpenJDK 15 and trim its size by removing unused components. Some projects only run with Java 15.
curl --silent -L -O https://download.java.net/java/GA/jdk15.0.2/0d1cfde4252546c6931946de8db48ee2/7/GPL/openjdk-15.0.2_linux-x64_bin.tar.gz && \
mkdir -p $JAVA_15_HOME
tar -xz --strip-components=1 -f openjdk-15.0.2_linux-x64_bin.tar.gz --directory $JAVA_15_HOME && \
rm -f openjdk-15.0.2_linux-x64_bin.tar.gz
rm -rf $JAVA_15_HOME/jmods $JAVA_15_HOME/lib/src.zip

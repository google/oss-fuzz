#!/bin/bash -eux
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

# Install java in a platform-aware way.

ARCHITECTURE=
case $(uname -m) in
    x86_64)
      ARCHITECTURE=x64
        ;;
    aarch64)
      ARCHITECTURE=aarch64
      ;;
    *)
      echo "Error: unsupported architecture: $(uname -m)"
      exit 1
      ;;
esac

wget -q https://download.java.net/java/GA/jdk17.0.2/dfd4a8d0985749f896bed50d7138ee7f/8/GPL/openjdk-17.0.2_linux-"$ARCHITECTURE"_bin.tar.gz -O /tmp/openjdk-17.0.2_linux-"$ARCHITECTURE"_bin.tar.gz
wget -q https://download.java.net/java/GA/jdk15.0.2/0d1cfde4252546c6931946de8db48ee2/7/GPL/openjdk-15.0.2_linux-"$ARCHITECTURE"_bin.tar.gz -O /tmp/openjdk-15.0.2_linux-"$ARCHITECTURE"_bin.tar.gz
cd /tmp
mkdir -p $JAVA_HOME
tar -xz --strip-components=1 -f openjdk-17.0.2_linux-"$ARCHITECTURE"_bin.tar.gz --directory $JAVA_HOME
rm -f openjdk-17.0.2_linux-"$ARCHITECTURE"_bin.tar.gz
rm -rf $JAVA_HOME/jmods $JAVA_HOME/lib/src.zip

# Install OpenJDK 15 and trim its size by removing unused components. Some projects only run with Java 15.
mkdir -p $JAVA_15_HOME
tar -xz --strip-components=1 -f openjdk-15.0.2_linux-"$ARCHITECTURE"_bin.tar.gz --directory $JAVA_15_HOME
rm -f openjdk-15.0.2_linux-"$ARCHITECTURE"_bin.tar.gz
rm -rf $JAVA_15_HOME/jmods $JAVA_15_HOME/lib/src.zip

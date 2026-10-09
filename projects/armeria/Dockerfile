# Copyright 2026 Google LLC
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

# Armeria resolves a GraalVM 17 toolchain at configuration time and compiles with an Azul toolchain.
# TODO: Remove GraalVM (here and in build.sh) once Armeria resolves it lazily, only for native image tasks.
RUN mkdir graalvm17 zulu17 && \
    curl -sSL https://github.com/graalvm/graalvm-ce-builds/releases/download/jdk-17.0.9/graalvm-community-jdk-17.0.9_linux-x64_bin.tar.gz \
      | tar xz --strip-components=1 -C graalvm17 && \
    curl -sSL https://cdn.azul.com/zulu/bin/zulu17.68.203-ca-jdk17.0.20.1-linux_x64.tar.gz \
      | tar xz --strip-components=1 -C zulu17

RUN git clone --depth 1 https://github.com/line/armeria armeria

COPY *.sh *.gradle *.java $SRC/

WORKDIR $SRC/armeria

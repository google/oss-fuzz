# Copyright 2020 Google Inc.
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

## This file was copied from envoy (with minor changes).

FROM gcr.io/oss-fuzz-base/base-builder

RUN apt-get update && apt-get -y install  \
    build-essential \
    openjdk-8-jdk   \
    make            \
    ninja-build     \
    curl            \
    autoconf        \
    libtool         \
    wget            \
    golang          \
    python          \
    rsync

# Install Bazelisk
RUN wget -O /usr/local/bin/bazel https://github.com/bazelbuild/bazelisk/releases/download/v0.0.8/bazelisk-linux-amd64; \
    chmod +x /usr/local/bin/bazel

RUN git clone --depth 1 https://github.com/GoogleCloudPlatform/esp-v2.git
WORKDIR $SRC/esp-v2/
COPY build.sh $SRC/

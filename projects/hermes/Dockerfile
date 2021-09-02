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

# Using Ubuntu 16.04 because of breakage on Ubuntu 20.04.
# See https://github.com/google/oss-fuzz/issues/6291 for more details.
FROM gcr.io/oss-fuzz-base/base-builder:xenial
# Delete line above and uncomment line below to upgrade to 20.04.
# FROM gcr.io/oss-fuzz-base/base-builder
RUN apt-get update && \
    apt-get install -y make autoconf automake libtool wget libicu-dev \
    ninja-build python zip libreadline-dev libatomic-ops-dev

RUN git clone https://github.com/facebook/hermes.git
WORKDIR hermes
COPY build.sh $SRC/

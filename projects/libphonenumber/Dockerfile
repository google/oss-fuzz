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
RUN apt-get update && apt-get install -y autoconf automake libtool g++ cmake-curses-gui libgtest-dev libre2-dev libicu-dev libboost-dev libboost-thread-dev libboost-system-dev binutils ninja-build liblzma-dev libz-dev pkg-config wget openjdk-8-jdk

WORKDIR $SRC/
RUN git clone https://github.com/google/libphonenumber

RUN wget https://github.com/unicode-org/icu/releases/download/release-55-2/icu4c-55_2-src.tgz && tar xzvf icu4c-55_2-src.tgz

COPY build.sh $SRC/
COPY phonefuzz.cc $SRC/

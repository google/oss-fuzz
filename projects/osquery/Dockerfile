# Copyright 2019 Google Inc.
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

FROM gcr.io/oss-fuzz-base/base-builder
MAINTAINER theopolis@osquery.io
RUN apt-get update
RUN apt-get install -y --no-install-recommends python python3 bison flex make wget xz-utils libunwind-dev

# Install specific git version.
RUN export GIT_VER=2.21.0 \
 && apt-get install -y libz-dev gettext nano libssl-dev autoconf libcurl4-openssl-dev \
 && wget https://github.com/git/git/archive/v$GIT_VER.tar.gz \
 && tar xf v$GIT_VER.tar.gz \
 && cd git-$GIT_VER/ \
 && make configure \
 && ./configure --with-openssl \
 && make -j4 install \
 && cd .. \
 && rm -rf v$GIT_VER.tar.gz git-$GIT_VER

# Installer newer cmake
RUN wget -q https://github.com/Kitware/CMake/releases/download/v3.14.6/cmake-3.14.6-Linux-x86_64.tar.gz \
 && tar xf cmake-3.14.6-Linux-x86_64.tar.gz -C /usr/local --strip 1 \
 && rm cmake-3.14.6-Linux-x86_64.tar.gz

RUN git clone --depth 1 https://github.com/osquery/osquery osquery

WORKDIR osquery
COPY build.sh $SRC/

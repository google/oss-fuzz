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
MAINTAINER arvid@libtorrent.org
RUN apt-get update && apt-get install -y wget libssl-dev

RUN wget --no-verbose https://dl.bintray.com/boostorg/release/1.69.0/source/boost_1_69_0.tar.gz
RUN tar xzf boost_1_69_0.tar.gz

RUN git clone --depth 1 --single-branch --branch RC_1_2 --recurse-submodules https://github.com/arvidn/libtorrent.git
WORKDIR libtorrent
COPY build.sh $SRC/


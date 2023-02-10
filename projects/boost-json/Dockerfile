# Copyright 2017 Google Inc.
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
#RUN apt-get update && apt-get install -y g++

RUN git clone --depth 1 --single-branch --branch master https://github.com/boostorg/boost.git
RUN pwd
RUN ls
RUN git -C boost submodule update --init libs/json
RUN git -C boost/libs/json checkout develop
RUN git -C boost submodule update --init --depth 1 \
libs/align/ \
libs/assert \
libs/config/ \
libs/container \
libs/container_hash/ \
libs/core \
libs/describe \
libs/headers/ \
libs/intrusive/ \
libs/move/ \
libs/mp11/ \
libs/predef/ \
libs/static_assert \
libs/system/ \
libs/throw_exception/ \
libs/type_traits/ \
libs/winapi/ \
libs/variant2/ \
tools/boost_install \
tools/build

WORKDIR boost
COPY build.sh $SRC/


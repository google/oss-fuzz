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
ARG SIM_DL_URL=https://downloads.sourceforge.net/project/ibmswtpm2/ibmtpm1332.tar.gz
RUN apt-get update && apt-get install -y make autoconf automake libtool libssl-dev curl tar g++
RUN mkdir ibmswtpm2 && \
  cd ibmswtpm2 && \
  curl -sSL "${SIM_DL_URL}" | tar xvz
WORKDIR ibmswtpm2/src
COPY build.sh $SRC/
COPY fuzzer.cc ./
COPY no_writes.patch $SRC/
RUN patch -p1 < $SRC/no_writes.patch

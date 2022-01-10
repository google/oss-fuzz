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
RUN apt-get update
RUN apt-get install -y --no-install-recommends python python3 bison flex make wget xz-utils libunwind-dev lsb-release build-essential libssl-dev

# osquery now needs at least version 3.21.4.
ENV cmakeVer 3.21.4
RUN wget https://github.com/Kitware/CMake/releases/download/v${cmakeVer}/cmake-${cmakeVer}-Linux-x86_64.tar.gz \
	&& tar xvf cmake-${cmakeVer}-Linux-x86_64.tar.gz -C /usr/local --strip 1 \
	&& rm cmake-${cmakeVer}-Linux-x86_64.tar.gz

RUN git clone --depth 1 https://github.com/osquery/osquery osquery

WORKDIR osquery
COPY build.sh $SRC/

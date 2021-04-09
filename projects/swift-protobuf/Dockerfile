# Copyright 2021 Google LLC
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
RUN apt-get update && apt install -y wget \
           binutils \
           libc6-dev \
           libcurl3 \
           libedit2 \
           libgcc-5-dev \
           libpython2.7 \
           libsqlite3-0 \
           libstdc++-5-dev \
           libxml2 \
           pkg-config \
           tzdata \
           zlib1g-dev

RUN wget https://swift.org/builds/swift-5.3.3-release/ubuntu1604/swift-5.3.3-RELEASE/swift-5.3.3-RELEASE-ubuntu16.04.tar.gz
RUN tar xzf swift-5.3.3-RELEASE-ubuntu16.04.tar.gz
RUN cp -r swift-5.3.3-RELEASE-ubuntu16.04/usr/* /usr/

RUN apt-get update && apt-get install -y build-essential make cmake ninja-build git python3 g++-multilib binutils-dev zlib1g-dev --no-install-recommends
RUN git clone --depth 1 https://github.com/llvm/llvm-project.git

RUN git clone --depth 1 https://github.com/apple/swift-protobuf.git
COPY build.sh $SRC
COPY llvmsymbol.diff $SRC
COPY *.swift $SRC/
WORKDIR $SRC/

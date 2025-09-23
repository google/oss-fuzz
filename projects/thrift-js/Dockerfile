# Copyright 2025 Google LLC
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

FROM gcr.io/oss-fuzz-base/base-builder-javascript

RUN apt-get update && apt-get install -y libssl-dev pkg-config autoconf automake libtool bison flex wget make

# ./b2 toolset=clang cxxflags="-stdlib=libc++" linkflags="-stdlib=libc++" -j$(nproc) install && \
RUN wget https://archives.boost.io/release/1.87.0/source/boost_1_87_0.tar.gz && \
    tar xzf boost_1_87_0.tar.gz && \
    cd boost_1_87_0 && \
    ./bootstrap.sh --with-toolset=clang && \
    ./b2 clean && \
    ./b2 toolset=clang -j$(nproc) install && \
    cd .. && \
    rm -rf boost_1_87_0

COPY build.sh $SRC/

RUN git clone --depth 1 https://github.com/apache/thrift.git

WORKDIR $SRC/thrift

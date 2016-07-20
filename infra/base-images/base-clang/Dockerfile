# Copyright 2016 Google Inc.
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

FROM libfuzzer/base

MAINTAINER mike.aizatsky@gmail.com

RUN apt-get install -y build-essential make cmake ninja-build git python2.7

# Checkout & build llvm+clang+deps
#
RUN mkdir /src /work
RUN cd /src && git clone --depth 1 http://llvm.org/git/llvm.git
RUN cd /src/llvm/tools && git clone --depth 1 http://llvm.org/git/clang.git
RUN cd /src/llvm/projects && git clone --depth 1 http://llvm.org/git/compiler-rt.git
RUN cd /src/llvm/projects && git clone --depth 1 http://llvm.org/git/libcxx.git
RUN cd /src/llvm/projects && git clone --depth 1 http://llvm.org/git/libcxxabi.git
RUN cd /src/llvm/projects && git clone --depth 1 http://llvm.org/git/lld.git
RUN mkdir -p /work/llvm && cd /work/llvm \
    && cmake -G "Ninja" -DCMAKE_BUILD_TYPE=Release -DLIBCXX_ENABLE_SHARED=OFF  -DLIBCXX_ENABLE_STATIC_ABI_LIBRARY=ON /src/llvm \
    && ninja
#RUN ln -s /work/llvm/bin/lld /work/llvm/bin/ld

RUN apt-get remove --purge -y cmake ninja-build python2.7 build-essential
RUN apt-get autoremove -y

ENV PATH="/work/llvm/bin:$PATH"

COPY env /work/llvm

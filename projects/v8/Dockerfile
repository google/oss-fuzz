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

FROM gcr.io/oss-fuzz-base/base-builder
RUN apt-get update && \
    apt-get install --no-install-recommends -y \
        lsb-release sudo pkg-config file libc++-18-dev libc++abi-18-dev
RUN git clone https://chromium.googlesource.com/chromium/tools/depot_tools.git
ENV PATH=/src/depot_tools:$PATH
RUN fetch v8 && cd v8 && git checkout HEAD && gclient sync -D
WORKDIR v8

RUN echo 'debconf debconf/frontend select Noninteractive' | debconf-set-selections
RUN ./build/install-build-deps.sh --no-prompt
COPY build.sh run_tests.sh $SRC/

ENV CLANG_TOOLCHAIN $SRC/v8/third_party/llvm-build/Release+Asserts

# Copyright 2023 Google LLC
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
RUN apt-get update && apt-get install -y make autoconf automake libtool
RUN git clone --depth 1 https://github.com/pytorch/cpuinfo

# Pre-download test dependencies (Google Test and Google Benchmark) so they're available offline
WORKDIR cpuinfo
RUN mkdir -p deps && \
    cd deps && \
    wget https://github.com/google/googletest/archive/refs/tags/v1.17.0.zip -O googletest.zip && \
    unzip googletest.zip && \
    mv googletest-1.17.0 googletest && \
    rm googletest.zip && \
    wget https://github.com/google/benchmark/archive/v1.9.1.zip -O benchmark.zip && \
    unzip benchmark.zip && \
    mv benchmark-1.9.1 googlebenchmark && \
    rm benchmark.zip

COPY build.sh *.c $SRC/
COPY run_tests.sh $SRC/

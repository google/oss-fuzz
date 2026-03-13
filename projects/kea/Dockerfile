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

FROM gcr.io/oss-fuzz-base/base-builder:ubuntu-24-04
RUN apt-get update && \
    apt-get install --no-install-recommends -y meson ninja-build pkg-config \
      build-essential python3 libssl-dev libboost-dev libboost-system-dev \
      libboost-filesystem-dev libboost-program-options-dev libboost-thread-dev \
      libpq-dev libmariadb-dev libkrb5-dev
RUN mkdir -p /opt/boost-headers && \
    wget https://archives.boost.io/release/1.83.0/source/boost_1_83_0.tar.gz && \
    tar -xzf boost_1_83_0.tar.gz -C /opt/boost-headers --strip-components=1 && \
    rm -f boost_1_83_0.tar.gz && mkdir -p /usr/local/include && \
    ln -s /opt/boost-headers/boost /usr/local/include/boost
RUN mkdir -p /src/log4cplus && \
    wget https://github.com/log4cplus/log4cplus/releases/download/REL_2_1_2/log4cplus-2.1.2.tar.gz && \
    tar -xzf log4cplus-2.1.2.tar.gz -C /src/log4cplus --strip-components=1 && \
    rm -f log4cplus-2.1.2.tar.gz
RUN python3 -m pip install --no-cache-dir --upgrade "meson>=1.1,<2"

RUN git clone https://gitlab.isc.org/isc-projects/kea kea
RUN git clone https://github.com/AdaLogics/ada-fuzzers ada-fuzzers
COPY build.sh $SRC/
WORKDIR kea

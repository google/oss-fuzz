# Copyright 2026 Google LLC
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
################################################################################


FROM gcr.io/oss-fuzz-base/base-builder:ubuntu-24-04

RUN apt-get update && \
    apt-get install -y gcc make libffi-dev pkg-config \
    zlib1g-dev libbz2-dev libsqlite3-dev libncurses-dev \
    libexpat1-dev libssl-dev libgdbm-dev tk-dev libgc-dev \
    liblzma-dev curl

RUN curl -fsSL -o /tmp/pypy2.7.tar.gz https://downloads.python.org/pypy/pypy2.7-v8.0.1-linux64.tar.gz && \
    echo "78674cdf95eb4cb1dd5a9b68a70200387111cb29467f8a472ab7cf07a251653c  /tmp/pypy2.7.tar.gz" | sha256sum -c - && \
    tar -xzf /tmp/pypy2.7.tar.gz -C /opt && \
    rm -f /tmp/pypy2.7.tar.gz && \
    ln -s /opt/pypy2.7-v8.0.1-linux64/bin/pypy /usr/local/bin/pypy

RUN git clone --depth 1 --branch py3.11 https://github.com/pypy/pypy.git pypy
RUN git clone --depth 1 --branch main https://github.com/StanFromIreland/pypy-fuzz.git
WORKDIR pypy
COPY build.sh $SRC/

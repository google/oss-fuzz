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

FROM gcr.io/oss-fuzz-base/base-builder
RUN apt-get update && apt-get install -y software-properties-common curl sudo mercurial autoconf bison texinfo libboost-all-dev cmake wget
RUN wget https://go.dev/dl/go1.17.5.linux-amd64.tar.gz && rm -rf /usr/local/go && tar -C /usr/local -xzf go1.17.5.linux-amd64.tar.gz && ldconfig
ENV PATH=$PATH:/usr/local/go/bin

RUN apt-get update && apt-get install -y \
    python-all-dev \
    python3-all-dev \
    python3-pip

# Install Python packages from PyPI
RUN pip3 install jinja2

RUN wget https://www.bytereef.org/software/mpdecimal/releases/mpdecimal-2.5.1.tar.gz
RUN git clone --depth 1 https://github.com/guidovranken/bignum-fuzzer
RUN git clone --depth 1 https://github.com/openssl/openssl
RUN hg clone https://gmplib.org/repo/gmp/ libgmp/
RUN git clone https://boringssl.googlesource.com/boringssl
RUN git clone --depth 1 -b development https://github.com/ARMmbed/mbedtls
COPY build.sh $SRC/

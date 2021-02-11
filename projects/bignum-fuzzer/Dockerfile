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
RUN apt-get update && apt-get install -y software-properties-common python-software-properties wget curl sudo mercurial autoconf bison texinfo libboost-all-dev cmake
RUN add-apt-repository -y ppa:gophers/archive && apt-get update && apt-get install -y golang-1.9-go
RUN ln -s /usr/lib/go-1.9/bin/go /usr/bin/go

RUN wget https://www.bytereef.org/software/mpdecimal/releases/mpdecimal-2.5.0.tar.gz
RUN git clone --recursive https://github.com/golang/go
RUN git clone --depth 1 https://github.com/guidovranken/bignum-fuzzer
RUN git clone --depth 1 https://github.com/openssl/openssl
RUN hg clone https://gmplib.org/repo/gmp/ libgmp/
RUN git clone https://boringssl.googlesource.com/boringssl
RUN git clone --depth 1 https://github.com/ARMmbed/mbedtls
COPY build.sh $SRC/

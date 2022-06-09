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
RUN apt-get update && apt-get install -y make autoconf automake libtool wget python bison flex texinfo lzip
RUN git clone https://github.com/ANSSI-FR/libecc.git
RUN git clone --depth 1 https://github.com/randombit/botan.git
RUN git clone https://github.com/wolfssl/wolfssl
RUN git clone --depth 1 https://github.com/guidovranken/cryptofuzz
RUN wget https://gmplib.org/download/gmp/gmp-6.2.1.tar.lz
RUN wget https://boostorg.jfrog.io/artifactory/main/release/1.74.0/source/boost_1_74_0.tar.bz2
COPY build.sh $SRC/

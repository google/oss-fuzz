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
RUN apt-get update && apt-get install -y make autoconf automake libtool wget \
                                         uuid-dev pkg-config libtool-bin \
                                         libbsd-dev

RUN git clone https://github.com/PCRE2Project/pcre2 pcre2 && \
    cd pcre2 && \
    ./autogen.sh && \
    ./configure && \
    make && \
    make install

RUN git clone https://github.com/AdaLogics/fuzz-headers

RUN wget https://github.com/libexpat/libexpat/releases/download/R_2_4_1/expat-2.4.1.tar.gz && \
    tar -xf expat-2.4.1.tar.gz && \
    cd expat-2.4.1 && \
    ./configure && \
    make && \
    make install

RUN git clone --depth=1 https://github.com/apache/httpd
WORKDIR httpd
COPY build.sh $SRC/
COPY fuzz_*.c $SRC/

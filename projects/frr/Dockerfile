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

RUN apt-get update && apt-get install -y git autoconf automake libtool make \
   libreadline-dev texinfo libjson-c-dev pkg-config bison flex python3-pip \
   libc-ares-dev python3-dev python3-sphinx build-essential libsystemd-dev \
   libsnmp-dev libcap-dev libelf-dev libpcre3-dev libpcre2-dev
RUN pip3 install pytest
RUN git clone https://github.com/CESNET/libyang.git

RUN git clone --depth 1 --branch fuzz https://github.com/FRRouting/frr

RUN git clone --depth 1 https://github.com/qlyoung/corpi
COPY build.sh $SRC
WORKDIR $SRC/frr

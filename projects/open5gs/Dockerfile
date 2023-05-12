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
RUN apt-get update && \
        apt-get upgrade -y && \
        DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        python3-pip python3-setuptools python3-wheel ninja-build build-essential flex bison git cmake meson libsctp-dev libgnutls28-dev libgcrypt-dev libssl-dev libidn11-dev libmongoc-dev libbson-dev libmicrohttpd-dev libcurl4-gnutls-dev libnghttp2-dev libtins-dev libtalloc-dev iproute2 ca-certificates netbase pkg-config && \
        apt-get install -y autoconf libtool-bin

RUN git clone https://github.com/yaml/libyaml.git
RUN git clone --depth=1 https://github.com/open5gs/open5gs.git

WORKDIR $SRC/libyaml
RUN ./bootstrap
RUN ./configure --enable-static --disable-shared
RUN make install

COPY build.sh $SRC/
WORKDIR $SRC/open5gs

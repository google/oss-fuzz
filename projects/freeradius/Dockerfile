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
RUN echo "deb http://packages.networkradius.com/extras/ubuntu/focal focal  main" > /etc/apt/sources.list.d/networkradius-extras.list
RUN apt-get install -y gnupg
RUN apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys BE18FC5A41382202
RUN apt-get update
RUN apt-get install -y libtalloc-dev libkqueue-dev libunwind-dev

# OpenSSL 1.1
ARG OPENSSL_VERSION=1.1.1g
ARG OPENSSL_HASH=ddb04774f1e32f0c49751e21b67216ac87852ceb056b75209af2443400636d46
RUN set -ex \
    && curl -s -O https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz \
    && echo "${OPENSSL_HASH}  openssl-${OPENSSL_VERSION}.tar.gz" | sha256sum -c \
    && tar -xzf openssl-${OPENSSL_VERSION}.tar.gz \
    && cd openssl-${OPENSSL_VERSION} \
    && ./Configure linux-x86_64 no-shared --static "$CFLAGS" \
    && make build_generated \
    && make libcrypto.a \
    && make install
ENV OPENSSL_ROOT_DIR=/usr/local/openssl-${OPENSSL_VERSION}

RUN git clone --depth 1 https://github.com/FreeRADIUS/freeradius-server.git
COPY build.sh $SRC
# COPY patch.diff $SRC
WORKDIR $SRC/freeradius-server

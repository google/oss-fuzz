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

# Run update a first time to get latest package definitions
RUN apt-get update && apt-get install -y gnupg
RUN apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys BE18FC5A41382202
RUN echo "deb http://packages.networkradius.com/extras/ubuntu/focal focal  main" > /etc/apt/sources.list.d/networkradius-extras.list

# Run update again to update the NR respository
RUN apt-get update && apt-get install -y libtalloc-dev libkqueue-dev libunwind-dev

# OpenSSL 3.2
ARG OPENSSL_VERSION=3.2.3
ARG OPENSSL_HASH=52b5f1c6b8022bc5868c308c54fb77705e702d6c6f4594f99a0df216acf46239
RUN set -ex \
    && curl -s -O https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz \
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

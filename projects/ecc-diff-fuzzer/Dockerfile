# Copyright 2018 Google Inc.
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
MAINTAINER p.antoine@catenacyber.fr
RUN apt-get update && apt-get install -y make cmake bzip2 autoconf automake libtool
RUN git clone --depth 1 https://github.com/catenacyber/elliptic-curve-differential-fuzzer.git ecfuzzer
RUN git clone --depth 1 https://github.com/ARMmbed/mbedtls.git mbedtls
RUN git clone --depth 1 https://github.com/ANSSI-FR/libecc.git libecc
RUN git clone --depth 1 https://github.com/openssl/openssl.git openssl
ADD https://www.gnupg.org/ftp/gcrypt/libgpg-error/libgpg-error-1.32.tar.bz2 libgpg-error-1.32.tar.bz2
RUN git clone --depth 1 https://github.com/gpg/libgcrypt gcrypt
RUN git clone --depth 1 https://github.com/weidai11/cryptopp cryptopp
WORKDIR $SRC/
COPY build.sh $SRC/

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
RUN apt-get update && apt-get install -y \
  build-essential libpcre2-dev libtool autoconf automake bison flex libssl-dev \
  libbison-dev libacl1 libacl1-dev lmdb-utils liblmdb-dev libpam0g-dev libtool \
  libyaml-dev libxml2-dev


RUN git clone --branch pcre2-10.39 https://github.com/PhilipHazel/pcre2 pcre2 && \
  cd pcre2 && \
  ./autogen.sh && \
  ./configure && \
  make all && \
  make install && \
  sed -i "s/\$libS\$libR \(-lpcre2-8$\)/\$libS\$libR -Wl,-Bstatic \1 -Wl,-Bdynamic/" /usr/local/bin/pcre2-config

RUN git clone --depth 1 https://github.com/cfengine/core --recursive
WORKDIR core
COPY build.sh string_fuzzer.c $SRC/

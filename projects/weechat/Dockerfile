# Copyright 2025 Google LLC
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
    cmake \
    curl \
    gcc \
    gem2deb \
    gettext \
    gnupg \
    guile-3.0-dev \
    libargon2-dev \
    libaspell-dev \
    libcjson-dev \
    libcurl3-gnutls-dev \
    libgcrypt20-dev \
    libgnutls28-dev \
    liblua5.3-dev \
    libncurses-dev \
    libperl-dev \
    libphp-embed \
    libsodium-dev \
    libxml2-dev \
    libzstd-dev \
    make \
    php-dev \
    pkg-config \
    python3-dev \
    tcl-dev \
    zlib1g-dev \
    ;
RUN git clone --depth=1 https://github.com/weechat/weechat
WORKDIR weechat
COPY build.sh $SRC/

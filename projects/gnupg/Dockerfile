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
RUN apt-get update && apt-get install -y make autoconf automake libtool gettext bzip2 gnupg

#wait for zesty, or backport ?
RUN curl -O https://www.gnupg.org/ftp/gcrypt/libgpg-error/libgpg-error-1.32.tar.bz2
RUN curl -O https://www.gnupg.org/ftp/gcrypt/libgcrypt/libgcrypt-1.8.2.tar.bz2
RUN curl -O https://www.gnupg.org/ftp/gcrypt/libassuan/libassuan-2.5.1.tar.bz2
RUN curl -O https://www.gnupg.org/ftp/gcrypt/libksba/libksba-1.3.5.tar.bz2
RUN curl -O https://www.gnupg.org/ftp/gcrypt/npth/npth-1.5.tar.bz2

RUN git clone --depth 1 git://git.gnupg.org/gnupg.git gnupg

WORKDIR gnupg
COPY fuzzgnupg.diff $SRC/fuzz.diff
COPY build.sh $SRC/

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
RUN apt-get update && apt-get install -y make autoconf automake libtool gettext bzip2 gnupg bison flex

RUN git clone --depth 1 git://git.gnupg.org/libgpg-error.git libgpg-error
RUN git clone --depth 1 git://git.gnupg.org/libgcrypt.git libgcrypt
RUN git clone --depth 1 git://git.gnupg.org/libassuan.git libassuan
RUN git clone --depth 1 git://git.gnupg.org/libksba.git libksba
RUN git clone --depth 1 git://git.gnupg.org/npth.git npth

RUN git clone --depth 1 git://git.gnupg.org/gnupg.git gnupg

WORKDIR gnupg
COPY fuzzgnupg.diff $SRC/fuzz.diff
COPY fuzz_* $SRC/
COPY build.sh $SRC/

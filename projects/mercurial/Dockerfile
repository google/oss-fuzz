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
RUN apt-get update && apt-get install -y \
  autoconf \
  automake \
  build-essential \
  curl \
  libbz2-dev \
  libncurses5-dev \
  libncursesw5-dev \
  libreadline-dev \
  libsqlite3-dev \
  libssl-dev \
  libtool \
  llvm \
  lzma-dev \
  make \
  python3-dev \
  tk-dev \
  wget \
  xz-utils \
  zlib1g-dev \
  mercurial
RUN cd $SRC && curl https://www.python.org/ftp/python/3.8.3/Python-3.8.3.tgz | tar xzf -
RUN hg clone https://www.mercurial-scm.org/repo/hg mercurial
WORKDIR mercurial
COPY build.sh $SRC/

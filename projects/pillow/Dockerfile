# Copyright 2019 Google Inc.
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
MAINTAINER guidovranken@gmail.com
RUN apt-get update && apt-get install -y make autoconf automake build-essential libbz2-dev libc6-dev libffi-dev libfreetype6-dev libgdbm-dev libjpeg-turbo8-dev liblcms2-dev libncursesw5-dev libreadline-dev libsqlite3-dev libssl-dev libtiff5-dev libtool libwebp-dev make python python-dev python-setuptools tk-dev wget zlib1g-dev libwebp-dev
RUN wget https://github.com/python/cpython/archive/v3.8.1.tar.gz
RUN git clone --depth 1 https://github.com/python-pillow/Pillow.git pillow
RUN git clone --depth 1 https://github.com/guidovranken/oss-fuzz-fuzzers
WORKDIR pillow
COPY build.sh $SRC/

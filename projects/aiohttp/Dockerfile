# Copyright 2022 Google LLC
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

FROM gcr.io/oss-fuzz-base/base-builder-python
RUN apt-get update && apt-get install -y \
  pkg-config \
  zlib1g \
  zlib1g-dev \
  libjpeg-dev \
  libpng-dev \
  npm \
  libffi-dev
RUN python3 -m pip install --upgrade pip
RUN git clone --recurse-submodules https://github.com/aio-libs/aiohttp
COPY build.sh $SRC/
COPY fuzz_* $SRC/aiohttp/

WORKDIR $SRC/aiohttp

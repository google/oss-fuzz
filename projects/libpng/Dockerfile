# Copyright 2016 Google Inc.
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

FROM ossfuzz/base-libfuzzer
MAINTAINER mmoroz@chromium.org
RUN apt-get install -y make autoconf automake libtool zlib1g-dev

RUN git clone --depth 1 git://git.code.sf.net/p/libpng/code libpng
WORKDIR libpng
COPY build.sh libpng_read_fuzzer.* png.dict $SRC/

# Copyright 2017 Google Inc.
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
RUN apt-get update && apt-get upgrade -y && apt-get install -y \
  autoconf2.13 \
  libc++1 \
  libc++abi1 \
  m4 \
  yasm \
  python

# This wrapper of cargo seems to interfere with our build system.
RUN rm -f /usr/local/bin/cargo

RUN git clone --depth=1 https://github.com/mozilla/gecko-dev mozilla-central
WORKDIR mozilla-central/js/src/
COPY build.sh $SRC/

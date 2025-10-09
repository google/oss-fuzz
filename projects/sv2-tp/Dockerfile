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

# Packages taken from:
# * https://github.com/sjors/sv2-tp/blob/master/doc/build-unix.md#dependency-build-instructions

RUN apt-get update && apt-get install -y \
  build-essential cmake pkgconf python3 \
  libcapnp-dev capnproto \
  && rm -rf /var/lib/apt/lists/*

RUN git clone --depth=1 https://github.com/sjors/sv2-tp.git sv2-tp
RUN git clone --depth=1 https://github.com/sjors/sv2-tp-qa-assets sv2-tp/assets && \
  rm -rf sv2-tp/assets/.git  # Remove git history to save storage
WORKDIR sv2-tp
COPY build.sh $SRC/

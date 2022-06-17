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
RUN \
  apt-get update && \
  apt-get install -y libtool libusb-1.0-0-dev pkg-config libglib2.0-dev && \
  apt-get clean

# Ubuntu 16.04 ships Meson 0.29 which doesn't support the "feature" option type.
#
# https://mesonbuild.com/Build-options.html#features
RUN python3 -m pip install --no-user --no-cache meson ninja

RUN git clone --depth 1 https://gitlab.freedesktop.org/spice/usbredir.git $SRC/spice-usbredir

WORKDIR $SRC/spice-usbredir
COPY build.sh $SRC/
# This is to fix Fuzz Introspector build by using LLVM old pass manager
# re https://github.com/ossf/fuzz-introspector/issues/305
ENV OLD_LLVMPASS 1

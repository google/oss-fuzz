# Copyright 2026 Google LLC
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

FROM gcr.io/oss-fuzz-base/base-builder:ubuntu-24-04

RUN apt-get update && apt-get install --reinstall -y \
    ninja-build cmake pkg-config \
    libsystemd-dev systemd-dev libboost-all-dev libssl-dev libnl-3-dev libnl-genl-3-dev \
    python3-pip zip && \
    pip3 install --break-system-packages meson inflection pyyaml mako jsonschema

RUN git clone --depth 1 https://github.com/openbmc/phosphor-networkd.git phosphor-networkd

WORKDIR $SRC/phosphor-networkd

COPY build.sh *.cpp *.dict *.patch *.build $SRC/
COPY corpus $SRC/corpus/

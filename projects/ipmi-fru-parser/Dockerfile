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

FROM gcr.io/oss-fuzz-base/base-builder

RUN apt-get update && apt-get install -y \
    ninja-build \
    pkg-config \
    python3-mako \
    python3-yaml \
    libsystemd-dev \
    systemd \
    libssl-dev \
    libboost-all-dev \
    libcereal-dev \
    libpam0g-dev

RUN pip3 install meson inflection mako pyyaml jsonschema

RUN git clone --depth 1 https://github.com/openbmc/ipmi-fru-parser.git ipmi-fru-parser

WORKDIR ipmi-fru-parser

COPY build.sh $SRC/
COPY fuzz_fru_parser.cpp $SRC/
COPY generate_seeds.py $SRC/

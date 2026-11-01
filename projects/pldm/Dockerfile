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

# Install ninja-build from apt, and the latest meson from pip3
RUN apt-get update && apt-get install -y ninja-build && pip3 install meson

# Install libpldm as a static library, disabling C++ bindings and tools
RUN git clone --depth 1 https://github.com/openbmc/libpldm.git libpldm && \
    cd libpldm && \
    meson setup build --buildtype=release --default-library=static -Dtests=false -Dbindings=[] -Dtools=[] && \
    ninja -C build install

# Clone the main pldm repository
RUN git clone --depth 1 https://gbmc.googlesource.com/pldm/ pldm

WORKDIR pldm

COPY pldm_package_parser_fuzzer.cc $SRC/
COPY pldm_shims/ $SRC/pldm_shims/
COPY build.sh $SRC/

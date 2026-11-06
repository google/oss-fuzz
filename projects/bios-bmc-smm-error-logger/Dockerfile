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

FROM gcr.io/oss-fuzz-base/base-builder:ubuntu-24-04

RUN apt-get update && apt-get install --reinstall -y \
    cmake ninja-build pkg-config \
    libsystemd-dev systemd-dev libboost-all-dev \
    python3-pip zip && \
    pip3 install --break-system-packages meson inflection pyyaml mako jsonschema

RUN git clone --depth 1 https://github.com/openbmc/bios-bmc-smm-error-logger.git bios-bmc-smm-error-logger

WORKDIR $SRC/bios-bmc-smm-error-logger

RUN git clone --depth 1 https://github.com/openbmc/libbej.git subprojects/libbej && \
    git clone --depth 1 https://github.com/nlohmann/json.git subprojects/nlohmann_json && \
    git clone --depth 1 https://github.com/openbmc/phosphor-dbus-interfaces.git subprojects/phosphor-dbus-interfaces && \
    git clone --depth 1 https://github.com/openbmc/sdbusplus.git subprojects/sdbusplus && \
    git clone --depth 1 https://github.com/openbmc/stdplus.git subprojects/stdplus && \
    git clone --depth 1 https://github.com/NVIDIA/stdexec.git subprojects/stdexec && \
    git clone --depth 1 https://github.com/fmtlib/fmt.git subprojects/fmt && \
    git clone --depth 1 https://github.com/Naios/function2.git subprojects/function2 && \
    cp subprojects/sdbusplus/subprojects/stdexec.wrap subprojects/ && \
    cp subprojects/stdplus/subprojects/fmt.wrap subprojects/ && \
    cp subprojects/stdplus/subprojects/function2.wrap subprojects/

COPY build.sh rde_fuzz.cpp fuzzing_meson.build generate_seeds.py rde_fuzz.dict rde_fuzz.options *.patch $SRC/

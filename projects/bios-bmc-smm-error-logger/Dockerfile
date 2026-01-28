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

FROM gcr.io/oss-fuzz-base/base-builder:ubuntu-24-04

RUN apt-get update && apt-get install --reinstall -y patchelf make ninja-build meson libgtest-dev libgmock-dev pkg-config libsystemd-dev python3-pip libboost-all-dev && pip3 install inflection pyyaml mako jsonschema --break-system-packages

RUN git clone https://github.com/openbmc/bios-bmc-smm-error-logger
COPY *.sh *.diff $SRC/
WORKDIR $SRC/bios-bmc-smm-error-logger

RUN git clone https://github.com/google/googletest.git --branch v1.15.2 subprojects/googletest
RUN git clone https://github.com/openbmc/libbej subprojects/libbej
RUN git clone https://github.com/nlohmann/json.git subprojects/nlohmann_json
RUN git clone https://github.com/openbmc/phosphor-dbus-interfaces.git subprojects/phosphor-dbus-interfaces


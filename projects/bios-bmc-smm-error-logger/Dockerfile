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

RUN apt-get update && apt-get install --reinstall -y libboost-all-dev git python3-pip python3-venv libmount-dev libcap-dev gperf vim clang-18 libc++-18-dev lsb-release wget software-properties-common gnupg systemd make pkg-config libsystemd-dev libfmt-dev cmake ninja-build

RUN python3 -m venv /env && . /env/bin/activate && pip install meson mako inflection pyyaml jinja2 jsonschema

# RUN git clone https://github.com/systemd/systemd.git && cd systemd && git checkout v255 && meson build && ninja -C build && ninja -C build install
ENV CC=clang-18 
ENV CXX=clang++-18

RUN git clone --branch fuzzing https://github.com/javanlacerda/bios-bmc-smm-error-logger
COPY build.sh $SRC/
WORKDIR $SRC/bios-bmc-smm-error-logger

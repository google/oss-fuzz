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

FROM gcr.io/oss-fuzz-base/base-builder

RUN apt-get update && apt-get -y install build-essential automake libtool git python libsystemd-dev

WORKDIR qubes-os

RUN git clone --single-branch https://github.com/QubesOS/qubes-app-linux-input-proxy $SRC/qubes-os/app-linux-input-proxy

RUN git clone --single-branch https://github.com/QubesOS/qubes-core-qubesdb $SRC/qubes-os/qubes-core-qubesdb

RUN git clone --single-branch https://github.com/QubesOS/qubes-core-qrexec $SRC/qubes-os/qubes-core-qrexec

COPY build.sh *.options $SRC/

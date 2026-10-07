# Copyright 2020 Google Inc.
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

FROM gcr.io/oss-fuzz-base/base-builder@sha256:19782f7fe8092843368894dbc471ce9b30dd6a2813946071a36e8b05f5b1e27e
# ! Project pinned after a clang update and an afl link error. Log: https://oss-fuzz-gcb-logs.storage.googleapis.com/log-e701b6fa-f3a0-414e-ad6e-0223e6d42ebd.txt
RUN apt-get update && apt-get install -y software-properties-common make autoconf build-essential wget lzip libtool
RUN git clone --depth 1 https://git.lysator.liu.se/nettle/nettle
COPY fuzz_*.c $SRC/
COPY build.sh $SRC/

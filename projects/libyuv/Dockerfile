#!/bin/bash -eu
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

FROM gcr.io/oss-fuzz-base/base-builder

RUN apt-get update
RUN git clone https://chromium.googlesource.com/libyuv/libyuv

WORKDIR $SRC
COPY libyuv_rotate_fuzzer.options $SRC/libyuv_rotate_fuzzer.options
COPY libyuv_rotate_fuzzer.cc $SRC/libyuv_rotate_fuzzer.cc
COPY build.sh $SRC/
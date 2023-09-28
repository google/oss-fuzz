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
RUN apt-get update -y && apt-get install -y make autoconf automake libtool \
	cmake pkg-config

# At the time of writing, OSS-Fuzz uses Ubuntu focal (20.04 LTS), but
# libabsl-dev isn't available until Ubuntu jammy (22.04 LTS), so build
# and install Abseil from source.
RUN git clone --depth=1 https://github.com/abseil/abseil-cpp

RUN git clone --depth 1 https://github.com/google/re2

COPY build.sh $SRC/

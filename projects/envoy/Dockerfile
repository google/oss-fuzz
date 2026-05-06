# Copyright 2018 Google Inc.
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


FROM gcr.io/oss-fuzz-base/base-builder@sha256:56905c98ae0083d14da0e7371184e694560a74750533f321ac0e9145af0e8d2e
# ! This project was pinned after a clang bump. Please remove the pin, Try to fix any build warnings and errors, as well as runtime errors
# see https://github.com/google/oss-fuzz/pull/12365


RUN apt-get update && apt-get -y install  \
	build-essential \
	openjdk-8-jdk   \
	make            \
    ninja-build     \
    curl            \
    autoconf        \
    libtool         \
    wget            \
    golang          \
    rsync           \
    python3

RUN git clone https://github.com/envoyproxy/envoy.git
WORKDIR $SRC/envoy/
COPY build.sh $SRC/
COPY WORKSPACE $SRC/envoy/

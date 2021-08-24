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

# Using Ubuntu 16.04 because of breakage on Ubuntu 20.04.
# See https://github.com/google/oss-fuzz/issues/6291 for more details.
FROM gcr.io/oss-fuzz-base/base-builder:xenial
# Delete line above and uncomment line below to upgrade to 20.04.
# FROM gcr.io/oss-fuzz-base/base-builder

# Installing optional libraries can utilize more code path and/or improve
# performance (avoid calling external programs).
RUN apt-get update && apt-get install -y make autoconf automake libtool pkg-config \
        libbz2-dev liblzo2-dev liblzma-dev liblz4-dev libz-dev \
        libxml2-dev libssl-dev libacl1-dev libattr1-dev lrzip \
	liblz4-tool lzop zstd lcab genisoimage jlha-utils rar default-jdk
RUN git clone --depth 1 https://github.com/libarchive/libarchive.git
WORKDIR libarchive
COPY build.sh libarchive_fuzzer.cc $SRC/

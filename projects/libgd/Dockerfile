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

# ubuntu-24-04: libgd's configure.ac now requires autoconf >= 2.71, and
# ./bootstrap.sh dies with "configure.ac:4: error: Autoconf version 2.71 or
# higher is required" on the default (Ubuntu 20.04) base image, which only has
# autoconf 2.69. Ubuntu 24.04 packages autoconf 2.71.
FROM gcr.io/oss-fuzz-base/base-builder:ubuntu-24-04
RUN apt-get update && \
    apt-get install -y make autoconf automake libtool pkg-config libz-dev
RUN git clone --depth 1 https://github.com/libgd/libgd
ADD https://lcamtuf.coredump.cx/afl/demo/afl_testcases.tgz $SRC/afl_testcases.tgz
WORKDIR libgd
COPY run_tests.sh build.sh *.cc $SRC/

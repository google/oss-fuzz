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

# base image with clang toolchain
FROM gcr.io/oss-fuzz-base/base-builder

# maintainer for this file

# install required packages to build your project
RUN apt-get update && apt-get install -y autoconf automake bison dh-autoreconf flex boost1.71-all-dev libluajit-5.1-dev libedit-dev libprotobuf-dev libssl-dev libtool make pkg-config protobuf-compiler ragel

# checkout all sources needed to build your project
RUN git clone https://github.com/PowerDNS/pdns.git pdns

# current directory for build script
WORKDIR pdns

# copy build script and other fuzzer files in src dir
COPY build.sh $SRC/
# This is to fix Fuzz Introspector build by using LLVM old pass manager
# re https://github.com/ossf/fuzz-introspector/issues/305
ENV OLD_LLVMPASS 1

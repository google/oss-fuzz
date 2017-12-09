# Copyright 2017 Google Inc.
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
MAINTAINER kcc@google.com
RUN apt-get update -y
RUN apt-get install -y autoconf automake libtool curl make g++ unzip wget git \
    binutils liblzma-dev libz-dev python-all cmake ninja-build subversion \
    pkg-config

# Get protobuf
RUN wget -qO- https://github.com/google/protobuf/releases/download/v3.3.0/protobuf-cpp-3.3.0.tar.gz | tar zxf -
# Get LLVM
RUN svn co http://llvm.org/svn/llvm-project/llvm/trunk llvm > svn.log 2>&1 
RUN cd llvm/tools && svn co http://llvm.org/svn/llvm-project/cfe/trunk clang -r $(cd ../ && svn info | grep Revision | awk '{print $2}') >> svn.log 2>&1 
RUN cd llvm/projects && svn co http://llvm.org/svn/llvm-project/compiler-rt/trunk compiler-rt -r $(cd ../ && svn info | grep Revision | awk '{print $2}')  >> svn.log 2>&1 
RUN cd llvm/tools/clang/tools && svn co http://llvm.org/svn/llvm-project/clang-tools-extra/trunk extra -r $(cd ../ && svn info | grep Revision | awk '{print $2}')  >> svn.log 2>&1

COPY build.sh $SRC/

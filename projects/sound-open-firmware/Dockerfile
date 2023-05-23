# Copyright 2020 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
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

# Base packages
RUN apt-get -y update
RUN apt-get install -y \
      gettext git libc6-dev-i386 libglib2.0-dev libncurses5-dev \
      libtool ninja-build python3-pip
RUN pip3 install west

# Zephyr SDK:
#
# Zephyr doesn't provide a clean "get the latest version" URL, but
# note that the use of the /latest/ path component at least ensures
# this will fail on a new release.
ARG SDK_VER=0.16.1
WORKDIR /root
RUN curl -L -o sdktmp.tar.xz https://github.com/zephyrproject-rtos/sdk-ng/releases/latest/download/zephyr-sdk-${SDK_VER}_linux-x86_64_minimal.tar.xz
RUN tar xf sdktmp.tar.xz; rm sdktmp.tar.xz
RUN zephyr-sdk-*/setup.sh -h

WORKDIR $SRC

# SOF itself (also pulls in Zephyr + modules via west)
RUN west init -m https://github.com/thesofproject/sof sof
RUN cd sof && west update

# Zephyr has its own python requirements
RUN pip3 install -r sof/zephyr/scripts/requirements-base.txt

# Hacks: the oss-fuzz-base/base-clang image (and its derivatives) lack
# some of the binutils-compatible LLVM tools that a SOF/Zephyr build
# relies on (when set to build with clang instead of gcc, obviously).
# Rather than figure out how to install them or why they're missing,
# just symlink to the GNU tools already installed.
RUN ln -s /usr/bin/objdump /usr/local/bin/llvm-objdump
RUN ln -s /usr/bin/strip /usr/local/bin/llvm-strip

# This is the worst.  SOF builds with C++ support even though it won't
# call it (there are eternal components that use C++, but nothing
# in-tree that can be fuzzed here).  For obscure compatibility
# reasons, when using clang Zephyr will still do the final link using
# binutils, which will pull in libstdc++ and not libc++.  Also, SOF is
# a 32 bit fuzz binary (it's firmware for a 32 bit DSP, and no one has
# done the work to make the source base 64 bit clean).  The oss-fuzz
# runner image does not have a i386 libstdc++.so.6!  But, well, we
# don't actually need any symbols from it, so...
RUN touch empty.c; gcc -m32 -c empty.c; ar rs /usr/lib32/libstdc++.a empty.o

COPY build.sh $SRC/

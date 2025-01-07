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
RUN apt-get -y update && apt-get -y install \
      gettext git libc6-dev-i386 libglib2.0-dev libncurses5-dev \
      libtool ninja-build software-properties-common python3 python3-pip

RUN python3 -m ensurepip --upgrade
RUN python3 -m pip install --upgrade pip
RUN pip3 install west

# Zephyr SDK:
COPY fetch-sdk.sh /root
WORKDIR /root/
RUN ./fetch-sdk.sh

# SOF itself (also pulls in Zephyr + modules via west)
RUN west init -m https://github.com/thesofproject/sof $SRC/sof_workspace
WORKDIR $SRC/sof_workspace
RUN west update

# Sort of a kludge: oss-fuzz has a "srcmap" tool to generate
# origin/commit info for .git directories automatically.  But it
# assumes that the remote is named "origin", which is not true for
# west (by design!).  Fix up a fake "origin"
RUN cd $SRC/sof_workspace; sh -c "$(west list -f '(cd {path}; git remote add origin {url});' | sed 1d)"

# Zephyr has its own python requirements
RUN pip3 install -r $SRC/sof_workspace/zephyr/scripts/requirements-base.txt

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
RUN cd $SRC; touch empty.c; gcc -m32 -c empty.c; ar rs /usr/lib32/libstdc++.a empty.o

# If a user is mounting their local source directory for debugging
# then we need to tell git to chill out and just take the repo. If we
# don't west fails with bogus error messages.
RUN git config --global --add safe.directory $SRC/sof_workspace/zephyr

COPY build.sh $SRC/

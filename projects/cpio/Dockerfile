# Copyright 2026 Google LLC
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
################################################################################
FROM gcr.io/oss-fuzz-base/base-builder
# cpio's git HEAD requires autoconf >= 2.71 and automake >= 1.16.5 to bootstrap,
# both newer than base-builder ships; install them from source.
RUN apt-get update && \
    apt-get install -y --no-install-recommends autopoint gettext bison rsync && \
    rm -rf /var/lib/apt/lists/*
RUN cd /tmp && \
    wget -q https://ftp.gnu.org/gnu/autoconf/autoconf-2.72.tar.gz && \
    tar xf autoconf-2.72.tar.gz && cd autoconf-2.72 && \
    ./configure >/dev/null && make -j$(nproc) >/dev/null && make install >/dev/null && \
    cd /tmp && rm -rf autoconf-2.72* && \
    wget -q https://ftp.gnu.org/gnu/automake/automake-1.16.5.tar.gz && \
    tar xf automake-1.16.5.tar.gz && cd automake-1.16.5 && \
    ./configure >/dev/null && make -j$(nproc) >/dev/null && make install >/dev/null && \
    cd /tmp && rm -rf automake-1.16.5* && hash -r
# cpio HEAD plus its two submodules (gnulib, paxutils) cloned over https so
# ./bootstrap runs offline.
RUN git clone --depth 1 https://git.savannah.gnu.org/git/cpio.git cpio && \
    git clone --depth 1 https://git.savannah.gnu.org/git/gnulib.git cpio/gnulib && \
    git clone --depth 1 https://git.savannah.gnu.org/git/paxutils.git cpio/paxutils
WORKDIR cpio
COPY fuzz_cpio.c build.sh $SRC/

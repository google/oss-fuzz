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

FROM gcr.io/oss-fuzz-base/base-builder
RUN apt-get update && apt-get install -y autoconf automake libtool pkg-config python3-pip
RUN unset CFLAGS CXXFLAGS && pip3 install -U meson ninja packaging
RUN git clone --depth 1 --branch v1.3.1 --no-tags https://github.com/madler/zlib.git
RUN git clone --depth 1 --no-tags https://gitlab.gnome.org/GNOME/glib
WORKDIR glib
COPY build.sh $SRC/
COPY 0001-deflate-Zero-initialise-the-prev-and-window-buffers.patch $SRC/

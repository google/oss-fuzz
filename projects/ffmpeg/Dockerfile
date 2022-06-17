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
RUN apt-get update && apt-get install -y make autoconf automake libtool build-essential \
    libass-dev libfreetype6-dev libsdl1.2-dev \
    libvdpau-dev libxcb1-dev libxcb-shm0-dev libdrm-dev \
    pkg-config texinfo libbz2-dev zlib1g-dev yasm cmake mercurial wget \
    xutils-dev libpciaccess-dev nasm rsync

RUN git clone https://git.ffmpeg.org/ffmpeg.git ffmpeg

RUN wget https://www.alsa-project.org/files/pub/lib/alsa-lib-1.1.0.tar.bz2
RUN git clone --depth 1 https://github.com/mstorsjo/fdk-aac.git
RUN git clone --depth 1 git://anongit.freedesktop.org/xorg/lib/libXext
RUN git clone --depth 1 https://github.com/intel/libva
RUN git clone --depth 1 -b libvdpau-1.2 git://people.freedesktop.org/~aplattner/libvdpau
RUN git clone --depth 1 https://chromium.googlesource.com/webm/libvpx
RUN git clone --depth 1 https://gitlab.xiph.org/xiph/ogg.git
RUN git clone --depth 1 https://gitlab.xiph.org/xiph/opus.git
RUN git clone --depth 1 https://gitlab.xiph.org/xiph/theora.git
RUN git clone --depth 1 https://gitlab.xiph.org/xiph/vorbis.git
RUN git clone --depth 1 https://gitlab.gnome.org/GNOME/libxml2.git

COPY build.sh group_seed_corpus.py $SRC/

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
MAINTAINER mmoroz@chromium.org
RUN apt-get update && apt-get install -y make autoconf automake libtool build-essential \
    libass-dev libfreetype6-dev libsdl1.2-dev \
    libvdpau-dev libxcb1-dev libxcb-shm0-dev \
    pkg-config texinfo libbz2-dev zlib1g-dev nasm yasm cmake mercurial wget \
    xutils-dev libpciaccess-dev

RUN git clone https://git.ffmpeg.org/ffmpeg.git ffmpeg

RUN wget ftp://ftp.alsa-project.org/pub/lib/alsa-lib-1.1.0.tar.bz2
RUN git clone git://anongit.freedesktop.org/mesa/drm
RUN git clone https://github.com/mstorsjo/fdk-aac.git
ADD https://sourceforge.net/projects/lame/files/latest/download lame.tar.gz
RUN git clone git://anongit.freedesktop.org/xorg/lib/libXext
RUN git clone git://anongit.freedesktop.org/git/xorg/lib/libXfixes
RUN git clone https://github.com/01org/libva
RUN git clone git://people.freedesktop.org/~aplattner/libvdpau
RUN git clone https://chromium.googlesource.com/webm/libvpx
RUN svn co http://svn.xiph.org/trunk/ogg
RUN git clone git://git.xiph.org/opus.git
RUN git clone git://git.xiph.org/theora.git
RUN git clone git://git.xiph.org/vorbis.git
RUN git clone git://git.videolan.org/git/x264.git
RUN hg clone https://bitbucket.org/multicoreware/x265

COPY build.sh group_seed_corpus.py $SRC/

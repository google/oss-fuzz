# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

FROM gcr.io/oss-fuzz-base/base-builder

# Install OBS dependencies and ffmpeg build dependencies
RUN apt-get update && apt-get install -y \
    # OBS dependencies
    libx264-dev libcurl4-openssl-dev libmbedtls-dev libgl1-mesa-dev libjansson-dev \
    libluajit-5.1-dev python3-dev libx11-dev libxcb-randr0-dev libxcb-shm0-dev libxcb-xinerama0-dev \
    libxcb-composite0-dev libxcomposite-dev libxinerama-dev libxcb1-dev libx11-xcb-dev libxcb-xfixes0-dev \
    swig libcmocka-dev libxss-dev libglvnd-dev libgles2-mesa libgles2-mesa-dev ninja-build \
    libpci-dev libqrcodegencpp-dev uthash-dev software-properties-common \
    extra-cmake-modules uuid-dev libpulse-dev  libdrm-dev \
    # FFmpeg build dependencies
    build-essential yasm nasm libvpx-dev libmp3lame-dev libopus-dev wget bzip2

RUN apt-get install -y pkg-config
# Download, build, and install FFmpeg 6.1.1
RUN cd /tmp && \
    wget https://ffmpeg.org/releases/ffmpeg-6.1.1.tar.bz2 && \
    tar xjvf ffmpeg-6.1.1.tar.bz2 && \
    cd ffmpeg-6.1.1 && \
    env CFLAGS="" CXXFLAGS="" LDFLAGS="" ./configure \
      --prefix=/usr/local \
      --enable-shared \
      --enable-gpl \
      --enable-libx264 \
      --enable-libvpx \
      --enable-libmp3lame \
      --enable-libopus && \
    make -j$(nproc) && \
    make install && \
    ldconfig && \
    # Clean up source files to reduce final image size
    cd / && rm -rf /tmp/ffmpeg-6.1.1*

RUN add-apt-repository ppa:okirby/qt6-backports
RUN apt update
RUN apt-get install -y qt6-tools-dev libqt6svg6-dev libqt6xml6 qt6-base-dev libqt6widgets6 nlohmann-json3-dev libqt6svg6 libxkbcommon-dev qt6-base-private-dev

# Clone OBS Studio and set up for the build
RUN git clone --recursive https://github.com/obsproject/obs-studio.git obs-studio
WORKDIR obs-studio

COPY build.sh $SRC
COPY fuzz_*.cpp $SRC
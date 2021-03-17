# Copyright 2021 Google LLC
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
RUN apt-get update && apt-get install -y make cmake autoconf \
    automake libtool gettext pkg-config build-essential \
    mercurial wget libeigen3-dev libflann-dev python python-dev 
    
# VTK deps
RUN apt-get update && apt-get install -y \
    libavcodec-dev libavformat-dev libavutil-dev libboost-dev \
    libdouble-conversion-dev libeigen3-dev libexpat1-dev \
    libfontconfig-dev libfreetype6-dev libgdal-dev libglew-dev \
    libhdf5-dev libjpeg-dev libjsoncpp-dev liblz4-dev liblzma-dev \
    libnetcdf-dev libnetcdf-cxx-legacy-dev libogg-dev libpng-dev \
    libpython3-dev libqt5opengl5-dev libqt5x11extras5-dev libsqlite3-dev \
    libswscale-dev libtheora-dev libtiff-dev libxml2-dev libxt-dev \
    qtbase5-dev qttools5-dev zlib1g-dev

# Install and build boost from source so we can have it use libc++
RUN wget https://sourceforge.net/projects/boost/files/boost/1.70.0/boost_1_70_0.tar.gz && \
    tar xzf boost_1_70_0.tar.gz && \
    cd boost_1_70_0 && \
    ./bootstrap.sh --with-toolset=clang && \
    ./b2 clean && \
    ./b2 toolset=clang cxxflags="-stdlib=libc++" linkflags="-stdlib=libc++" -j$(nproc) install && \
    cd .. && \
    rm -rf boost_1_70_0]

RUN git clone --depth 1 https://github.com/PointCloudLibrary/pcl
COPY build.sh $SRC/
WORKDIR $SRC/

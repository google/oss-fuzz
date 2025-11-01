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
RUN apt-get update && \
    apt-get install -y pkg-config libtool cmake make autoconf automake ninja-build

# Build a newer version of HDF5 than what Ubuntu 20.04 has (which is version 1.10.x)
WORKDIR /tmp
RUN wget https://github.com/HDFGroup/hdf5/releases/download/hdf5-1_14_3/hdf5-1_14_3.tar.gz
RUN echo "126b800e9b87f65e7e7ffa58ee006607bab03a8e11e5209ea3d5c0c331321d43  hdf5-1_14_3.tar.gz" > hdf5.sum
RUN shasum -a 256 -c hdf5.sum
RUN tar xf hdf5-1_14_3.tar.gz
RUN mkdir -p hdfsrc/build
WORKDIR /tmp/hdfsrc/build
RUN cmake -G "Unix Makefiles" \
    -DCMAKE_INSTALL_PREFIX:PATH=/opt \
    -DBUILD_SHARED_LIBS:BOOL=OFF \
    -DBUILD_TESTING:BOOL=OFF \
    -DCMAKE_VERBOSE_MAKEFILES:BOOL=ON \
    -DHDF5_BUILD_EXAMPLES:BOOL=OFF \
    -DHDF5_BUILD_TOOLS:BOOL=OFF \
    -DHDF5_ENABLE_SANITIZERS:BOOL=ON \
    -DHDF5_ENABLE_Z_LIB_SUPPORT:BOOL=ON \
    -DHDF5_BUILD_CPP_LIB=ON \
    -DHDF5_BUILD_HL_LIB:BOOL=ON \
    -DHDF5_ENABLE_SZIP_SUPPORT:BOOL=OFF \
    .. && \
    cmake --build . --verbose --config Release -j$(nproc) && \
    make install

# Build libxml2 statically (use version 2.10.1 as newer versions require Automake 1.16.3, but Ubuntu 20.04 only supplies 1.16.1)
WORKDIR /tmp
RUN wget https://gitlab.gnome.org/GNOME/libxml2/-/archive/v2.10.1/libxml2-v2.10.1.tar.gz
RUN echo "c89e5d4eb873f209bace159fc1c76e40ce89f4dc94ac382a6c17032624e2840c  libxml2-v2.10.1.tar.gz" > libxml2.sum
RUN shasum -a 256 -c libxml2.sum
RUN tar xf libxml2-v2.10.1.tar.gz
WORKDIR /tmp/libxml2-v2.10.1
RUN ./autogen.sh \
    --prefix=/opt \
    --disable-shared \
    --without-debug \
    --without-http \
    --without-lzma \
    --without-zlib \
    --without-python && \
    make -j$(nproc) && \
    make install

WORKDIR $SRC

RUN git clone --depth 1 https://github.com/OpenNavigationSurface/BAG bag

RUN cp $SRC/bag/fuzzers/build.sh $SRC/

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
MAINTAINER even.rouault@spatialys.com
# curl needed to fetch sqlite3
# tcl needed to build sqlite3
# docbook2x needed o build expat
RUN apt-get update && apt-get install -y make autoconf automake libtool g++ curl tcl docbook2x
# libpng12-dev libjpeg-dev libgif-dev liblzma-dev libgeos-dev libcurl4-gnutls-dev libproj-dev libxml2-dev libexpat-dev libxerces-c-dev libnetcdf-dev netcdf-bin libpoppler-dev libspatialite-dev libhdf4-alt-dev libhdf5-serial-dev  poppler-utils libfreexl-dev unixodbc-dev libwebp-dev libepsilon-dev libpcre3-dev
# libpodofo-dev  libcrypto++-dev
RUN git clone --depth 1 https://github.com/OSGeo/gdal gdal
RUN git clone --depth 1 https://github.com/libexpat/libexpat gdal/libexpat
RUN mkdir gdal/sqlite3 && \
    cd gdal/sqlite3 && \
    curl 'https://www.sqlite.org/src/tarball?uuid=trunk' -o sqlite3.tar.gz && \
    tar xzf sqlite3.tar.gz
WORKDIR gdal
COPY build.sh $SRC/

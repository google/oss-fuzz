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

FROM gcr.io/oss-fuzz-base/base-builder:ubuntu-24-04

RUN apt-get update && \
    apt-get install -y make autoconf automake libtool g++ curl cmake sqlite3 pkg-config

# Using this temporary branch while the pull request in google/ossfuzz has not been yet merged
# Once it has been, this ossfuzz_ubuntu_2404 branch will be merged back to OSGeo/gdal master
RUN git clone --depth 1 --branch ossfuzz_ubuntu_2404 https://github.com/rouault/gdal gdal
#RUN git clone --depth 1 https://github.com/OSGeo/gdal gdal

RUN cp gdal/fuzzers/build.sh $SRC/

WORKDIR gdal


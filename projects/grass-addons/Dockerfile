# Copyright 2025 The OSS-Fuzz Authors. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

FROM gcr.io/oss-fuzz-base/base-builder

# Install dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    autoconf \
    automake \
    libtool \
    pkg-config \
    libgdal-dev \
    libgeos-dev \
    libproj-dev \
    libtiff-dev \
    libpng-dev \
    libjpeg-dev \
    libzstd-dev \
    python3-dev \
    python3-pip \
    flex \
    bison

# Copy the source code
COPY . $SRC/grass-addons
WORKDIR $SRC/grass-addons

# Copy build script to the correct location
COPY build.sh $SRC/build.sh
RUN chmod +x $SRC/build.sh
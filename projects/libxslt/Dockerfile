# Copyright 2019 Google Inc.
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
MAINTAINER wellnhofer@aevum.de

# Note that we don't use the system libxml2 but a custom instrumented build.
# libgcrypt is required for the crypto extensions of libexslt.
RUN apt-get update && apt-get install -y --no-install-recommends \
    make autoconf automake libtool pkg-config \
    libgcrypt-dev
RUN git clone --depth 1 https://gitlab.gnome.org/GNOME/libxml2.git
RUN git clone --depth 1 https://gitlab.gnome.org/GNOME/libxslt.git
WORKDIR libxslt
COPY build.sh $SRC/

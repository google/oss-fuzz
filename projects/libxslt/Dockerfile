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

# Note that we don't use the system libxml2 but a custom instrumented build.
# libgcrypt is required for the crypto extensions of libexslt.
RUN apt-get update && apt-get install -y --no-install-recommends \
    make autoconf libtool pkg-config \
    libgcrypt-dev
# Build requires automake 1.16.3
RUN curl -LO http://mirrors.kernel.org/ubuntu/pool/main/a/automake-1.16/automake_1.16.5-1.3_all.deb && \
    apt install ./automake_1.16.5-1.3_all.deb
RUN git clone --depth 1 https://gitlab.gnome.org/GNOME/libxml2.git
RUN git clone --depth 1 https://gitlab.gnome.org/GNOME/libxslt.git
WORKDIR libxslt
COPY build.sh $SRC/

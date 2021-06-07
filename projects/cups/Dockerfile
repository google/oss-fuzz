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
RUN apt-get update && apt install -y autoconf build-essential libavahi-client-dev \
    libgnutls28-dev libkrb5-dev libnss-mdns libpam-dev \
    libsystemd-dev libusb-1.0-0-dev zlib1g-dev
RUN git clone --depth 1 https://github.com/OpenPrinting/cups/
COPY build.sh $SRC
COPY fuzz*.c $SRC
WORKDIR $SRC/cups

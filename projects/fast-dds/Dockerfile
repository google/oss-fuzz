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
RUN apt-get update && apt install -y autoconf automake pkg-config
RUN git clone --depth 1 https://github.com/leethomason/tinyxml2
RUN git clone --depth 1 --branch asio-1-18-1 https://github.com/chriskohlhoff/asio/
RUN git clone --depth 1 https://github.com/eProsima/Fast-CDR.git
RUN git clone --depth 1 https://github.com/eProsima/foonathan_memory_vendor.git
RUN git clone --depth 1 https://github.com/eProsima/Fast-DDS.git
COPY build.sh $SRC
WORKDIR $SRC/Fast-DDS
# This is to fix Fuzz Introspector build by using LLVM old pass manager
# re https://github.com/ossf/fuzz-introspector/issues/305
ENV OLD_LLVMPASS 1

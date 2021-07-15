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
RUN apt-get update && apt-get install -y make autoconf automake libtool wget libpcre3 libpcre3-dev libaprutil1 libaprutil1-dev
RUN wget https://downloads.apache.org//httpd/httpd-2.4.48.tar.bz2 && tar -xf httpd-2.4.48.tar.bz2
WORKDIR httpd-2.4.48

COPY build.sh $SRC/
COPY fuzz_*.c $SRC/

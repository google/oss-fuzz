# Copyright 2018 Google Inc.
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
MAINTAINER security@ntp.org
RUN apt-get update && apt-get install -y make autoconf automake libtool bison flex
#TODO use bitkeeper repo from http://bk.ntp.org
ADD http://www.eecis.udel.edu/~ntp/ntp_spool/ntp4/ntp-dev/ntp-dev-4.3.99.tar.gz ntp-dev.tar.gz
WORKDIR $SRC
COPY build.sh $SRC/
COPY patch.diff $SRC/

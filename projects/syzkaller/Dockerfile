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
MAINTAINER mmoroz@chromium.org
ADD https://dl.google.com/go/go1.12.9.linux-amd64.tar.gz go.tar.gz
RUN tar xzf go.tar.gz -C $SRC/
ENV GOPATH $SRC
ENV PATH $SRC/go/bin:$GOPATH/bin:$PATH

RUN go get -u -d github.com/google/syzkaller/...

RUN git clone --depth 1 https://github.com/google/syzkaller.git syzkaller
WORKDIR syzkaller
COPY build.sh $SRC/

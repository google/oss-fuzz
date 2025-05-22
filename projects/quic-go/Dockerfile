# Copyright 2020 Google Inc.
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

FROM gcr.io/oss-fuzz-base/base-builder-go

RUN git clone --depth 1 https://github.com/quic-go/qpack/ $GOPATH/src/github.com/quic-go/qpack
RUN git clone --depth 1 https://github.com/quic-go/quic-go/ $GOPATH/src/github.com/quic-go/quic-go

RUN cp $GOPATH/src/github.com/quic-go/quic-go/oss-fuzz.sh $SRC/build.sh
# Local testing:
# 1. copy oss-fuzz.sh from quic-go repo to projects/quic-go
# 2. uncomment this line
# 3. run infra/helper.py build_image quic-go
# COPY oss-fuzz.sh $SRC/build.sh

RUN chmod +x $SRC/build.sh

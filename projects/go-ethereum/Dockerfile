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

FROM gcr.io/oss-fuzz-base/base-builder

RUN cd $GOPATH/src && \
  mkdir -p github.com/ethereum && \
  cd github.com/ethereum && \
  git clone --depth=1 --single-branch  https://github.com/ethereum/go-ethereum && \
  cd go-ethereum && go mod download

RUN cp $GOPATH/src/github.com/ethereum/go-ethereum/oss-fuzz.sh $SRC/build.sh
# Enable this for easier local testing / repro
#ADD build.sh $SRC/build.sh

RUN cp $SRC/go-ethereum/oss-fuzz.sh $SRC/build.sh
WORKDIR $SRC/


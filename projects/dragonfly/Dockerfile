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
RUN go get	github.com/go-openapi/swag \
		github.com/go-openapi/validate \
		gopkg.in/warnings.v0 \
		github.com/gorilla/mux \
		github.com/prometheus/client_golang/prometheus \ 
		github.com/pkg/errors \
		github.com/sirupsen/logrus \
		gopkg.in/gcfg.v1 \
		github.com/valyala/fasthttp \
		gopkg.in/natefinch/lumberjack.v2 \
		github.com/emirpasic/gods/maps/treemap \
		github.com/emirpasic/gods/utils \
		github.com/willf/bitset
RUN git clone https://github.com/dragonflyoss/Dragonfly
COPY build.sh $SRC/
WORKDIR $SRC/Dragonfly

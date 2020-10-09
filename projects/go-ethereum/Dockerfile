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

RUN go get github.com/ethereum/go-ethereum
RUN go get golang.org/x/sys/cpu
RUN go get github.com/go-stack/stack
RUN go get github.com/deckarep/golang-set
RUN go get github.com/golang/snappy
RUN go get github.com/gorilla/websocket
RUN go get github.com/hashicorp/golang-lru
RUN go get github.com/holiman/uint256
RUN go get github.com/olekukonko/tablewriter
RUN go get github.com/prometheus/tsdb/fileutil
RUN go get github.com/shirou/gopsutil/cpu
RUN go get github.com/steakknife/bloomfilter
RUN go get github.com/syndtr/goleveldb/leveldb
RUN go get github.com/syndtr/goleveldb/leveldb/errors
RUN go get github.com/syndtr/goleveldb/leveldb/filter
RUN go get github.com/syndtr/goleveldb/leveldb/opt
RUN go get github.com/syndtr/goleveldb/leveldb/util
RUN go get github.com/VictoriaMetrics/fastcache
RUN go get github.com/aristanetworks/goarista/monotime
RUN go get github.com/pborman/uuid
RUN go get github.com/rjeczalik/notify
RUN go get github.com/google/gofuzz
 
COPY build.sh $SRC/
WORKDIR $SRC/

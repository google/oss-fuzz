#!/bin/bash -eu
# Copyright 2026 Google LLC
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

# Copy fuzz targets to their packages
cp $SRC/dnsmessage_fuzz_test.go $SRC/golang-net/dns/dnsmessage/fuzz_test.go
cp $SRC/hpack_fuzz_test.go $SRC/golang-net/http2/hpack/fuzz_test.go

cd $SRC/golang-net

# Build fuzz targets for DNS message parser
compile_go_fuzzer golang.org/x/net/dns/dnsmessage FuzzDNSMessageParse FuzzDNSMessageParse
compile_go_fuzzer golang.org/x/net/dns/dnsmessage FuzzDNSName FuzzDNSName

# Build fuzz targets for HTTP/2 HPACK
compile_go_fuzzer golang.org/x/net/http2/hpack FuzzHpackDecode FuzzHpackDecode
compile_go_fuzzer golang.org/x/net/http2/hpack FuzzHpackRoundTrip FuzzHpackRoundTrip

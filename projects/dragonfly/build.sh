#!/bin/bash -eu
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

cd /src/Dragonfly
cat > pkg/digest/fuzz.go << 'FUZZ_EOF'
package digest

import (
	"strings"
)

func FuzzParse(data []byte) int {
	s := string(data)
	s = strings.TrimSpace(s)
	_, err := Parse(s)
	if err != nil {
		return 0
	}
	return 1
}
FUZZ_EOF

cat > pkg/net/http/fuzz.go << 'FUZZ_EOF'
package http

import (
	"strconv"
	"strings"
)

func FuzzParseRange(data []byte) int {
	s := string(data)
	parts := strings.SplitN(s, "\n", 2)
	if len(parts) < 2 {
		return 0
	}
	rangeStr := parts[0]
	sizeStr := strings.TrimSpace(parts[1])
	size, err := strconv.ParseInt(sizeStr, 10, 64)
	if err != nil {
		return 0
	}
	_, _ = ParseRange(rangeStr, size)
	_, _ = ParseURLMetaRange(rangeStr, size)
	return 1
}
FUZZ_EOF

cat > pkg/dfnet/fuzz.go << 'FUZZ_EOF'
package dfnet

func FuzzNetAddrJSON(data []byte) int {
	var addr NetAddr
	if err := addr.UnmarshalJSON(data); err != nil {
		return 0
	}
	return 1
}
FUZZ_EOF

compile_go_fuzzer d7y.io/dragonfly/v2/pkg/digest FuzzParse fuzz_digest_parse
compile_go_fuzzer d7y.io/dragonfly/v2/pkg/net/http FuzzParseRange fuzz_http_range
compile_go_fuzzer d7y.io/dragonfly/v2/pkg/dfnet FuzzNetAddrJSON fuzz_dfnet_json

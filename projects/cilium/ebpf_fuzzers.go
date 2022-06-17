// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package btf

import (
	"bytes"

	"github.com/cilium/ebpf/internal"
)

func FuzzLoadRawSpec(data []byte) int {
	_, _ = LoadRawSpec(bytes.NewReader(data), internal.NativeEndian)
	return 1
}

func FuzzLoadSpecFromReader(data []byte) int {
	_, _ = LoadSpecFromReader(bytes.NewReader(data))
	return 1
}

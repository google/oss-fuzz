// Copyright 2026 Google LLC
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

package intelrdt

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/opencontainers/runc/libcontainer/configs"
)

func FuzzParseMonFeatures(data []byte) int {
	_, _ = parseMonFeatures(strings.NewReader(string(data)))
	return 1
}

func FuzzSetCacheScema(data []byte) int {
	if len(data)%2 != 0 {
		return -1
	}

	half := len(data) / 2
	before := string(data[:half])
	after := string(data[half:])

	dir, err := os.MkdirTemp("", "intelrdt-fuzz-")
	if err != nil {
		return 0
	}
	defer os.RemoveAll(dir)

	resctrl := filepath.Join(dir, "resctrl")
	if err := os.MkdirAll(resctrl, 0o755); err != nil {
		return 0
	}

	oldRoot := root
	root = func() (string, error) {
		return resctrl, nil
	}
	defer func() {
		root = oldRoot
	}()

	if err := os.WriteFile(
		filepath.Join(resctrl, "schemata"),
		[]byte(before+"\n"),
		0o644,
	); err != nil {
		return 0
	}

	config := &configs.Config{
		IntelRdt: &configs.IntelRdt{
			L3CacheSchema: after,
		},
	}

	_ = NewManager(config, "", resctrl).Set(config)

	return 1
}


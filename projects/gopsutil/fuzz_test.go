// Copyright 2023 Google LLC
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

package process

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func init() {
	os.Setenv("HOST_PROC", ".")
}

func FuzzTest(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		p := &Process{Pid: int32(1)}
		if len(data) < 5 {
			return
		}
		err := os.Mkdir("1", 0750)
		if err != nil {
			panic(err)
		}
		defer os.RemoveAll("1")
		file := filepath.Join(".", "1", "limits")
		err = os.WriteFile(file, data, 0666)
		if err != nil {
			panic(err)
		}
		p.RlimitUsageWithContext(context.Background(), true)
	})
}

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

package wal

import (
	"io/ioutil"
	"os"

	"go.uber.org/zap"
)

func FuzzWalCreate(data []byte) int {
	p, err := ioutil.TempDir("/tmp", "waltest")
	if err != nil {
		return -1
	}
	defer os.RemoveAll(p)
	w, err := Create(zap.NewExample(), p, data)
	if err != nil {
		return 0
	}
	defer w.Close()
	return 1
}

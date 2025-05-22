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

package blobstore

import (
	"bytes"
	"net/http"
	"testing"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
)

func FuzzParseUpload(f *testing.F) {
	f.Fuzz(func(t *testing.T, body, headers []byte) {
		r, err := http.NewRequest("POST", "", bytes.NewReader(body))
		if err != nil {
			return
		}
		ff := fuzz.NewConsumer(headers)
		h := make(map[string][]string, 0)
		ff.FuzzMap(&h)
		if len(h) == 0 {
			return
		}
		_, ok := h["Content-Type"]
		if !ok {
			hSlice := make([]string, 0)
			err := ff.CreateSlice(&hSlice)
			if err != nil {
				return
			}
			h["Content-Type"] = hSlice
		}
		r.Header = h
		ParseUpload(r)
	})
}

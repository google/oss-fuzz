// Copyright 2022 Google LLC
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

package h2c

import (
	"bytes"
	"fmt"
	"github.com/argoproj/argo-events/eventsources/common/webhook"
	"golang.org/x/net/http2"
	"io"
	"net/http"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
)

func FuzzH2c(data []byte) int {
	if len(data) < 10 {
		return 0
	}
	if len(data)%2 != 0 {
		return 0
	}
	data1 := data[:len(data)/10]
	data2 := data[(len(data)/10)+1:]
	f1 := fuzz.NewConsumer(data1)
	headerMap := make(map[string][]string)
	err := f1.FuzzMap(&headerMap)
	if err != nil {
		return 0
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "Hello world")
	})
	h2s := &http2.Server{
		// ...
	}
	h := NewHandler(handler, h2s)
	w := &webhook.FakeHttpWriter{}
	r := &http.Request{
		Body: io.NopCloser(bytes.NewReader(data2)),
	}
	r.Header = headerMap
	h.ServeHTTP(w, r)
	return 1
}

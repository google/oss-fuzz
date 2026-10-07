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
	"bufio"
	"bytes"
	"context"
	"fmt"
	"golang.org/x/net/http2"
	"io/ioutil"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"runtime"
	"strings"
)

type FakeHttpWriter struct {
	HeaderStatus int
	Payload      []byte
}

func (f *FakeHttpWriter) Header() http.Header {
	return http.Header{}
}

func (f *FakeHttpWriter) Write(body []byte) (int, error) {
	f.Payload = body
	return len(body), nil
}

func (f *FakeHttpWriter) WriteHeader(status int) {
	f.HeaderStatus = status
}

func (f *FakeHttpWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	r1 := bytes.NewReader([]byte{})
	r2 := bufio.NewReader(r1)
	w := bufio.NewWriter(ioutil.Discard)
	rw := bufio.NewReadWriter(r2, w)
	return nil, rw, nil
}

// We ignore these panics, as they don't represent real bugs.
func catchPanics() {
	if r := recover(); r != nil {
		var err string
		switch r.(type) {
		case string:
			err = r.(string)
		case runtime.Error:
			err = r.(runtime.Error).Error()
		case error:
			err = r.(error).Error()
		}
		// Very hacky for now, but it rids us of a lot of instantiation
		if strings.Contains(err, "invalid memory address or nil pointer dereference") {
			return
		} else {
			panic(err)
		}
	}
}

func FuzzH2c(data []byte) int {
	if len(data) < 10 {
		return 0
	}
	headerMap := make(map[string][]string)
	headerMap[textproto.CanonicalMIMEHeaderKey("Upgrade")] = []string{"h2c"}
	headerMap[textproto.CanonicalMIMEHeaderKey("Connection")] = []string{"HTTP2-Settings"}
	headerMap[textproto.CanonicalMIMEHeaderKey("HTTP2-Settings")] = []string{""}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "Hello world")
	})
	h2s := &http2.Server{
		// ...
	}
	h := NewHandler(handler, h2s)
	w := &FakeHttpWriter{}
	r, err := http.NewRequestWithContext(context.Background(), "PUT", "nil", bytes.NewReader(data))
	if err != nil {
		return -1
	}
	r.Header = headerMap
	u, err := url.Parse("http://localhost:8001")
	if err != nil {
		return 0
	}
	r.URL = u
	defer catchPanics()
	h.ServeHTTP(w, r)
	return 1
}

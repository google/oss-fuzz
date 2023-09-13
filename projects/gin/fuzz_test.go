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

package gin

import (
	"net/http"
)
import (
	"net/http/httptest"
)
import (
	"testing"
)

func FuzzTestContextNegotiationFormatWithAccept(f *testing.F) {
	f.Add(MIMEJSON, MIMEXML, MIMEHTML)
	f.Fuzz(func(t *testing.T, data1 string, data2 string, data3 string) {
		c, _ := CreateTestContext(httptest.NewRecorder())
		c.Request, _ = http.NewRequest("POST", "/", nil)
		c.Request.Header.Add("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9;q=0.8")
		c.NegotiateFormat(data1, data2)
		c.NegotiateFormat(data2, data3)
		c.NegotiateFormat(data1)
	})
}

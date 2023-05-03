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

package yaml

import (
	"bytes"
	"testing"
)

type FuzzType struct {
	field1 string
	Field2 string
	field3 []byte
	Field4 []byte
}

func FuzzDecode(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		d := NewDecoder(bytes.NewReader(data))
		d.Decode(&FuzzType{})
	})
}

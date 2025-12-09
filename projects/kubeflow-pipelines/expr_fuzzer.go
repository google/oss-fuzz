// Copyright 2025 Google LLC
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

package expression

import (
	"testing"

	"google.golang.org/protobuf/types/known/structpb"
)

func FuzzExprSelect(f *testing.F) {
	f.Fuzz(func(t *testing.T, input1, input2, input3, input4 string, inputType uint8) {
		var input *structpb.Value
		switch int(inputType) % 2 {
		case 0:
			input = structpb.NewStringValue(input1)
		case 1:
			m := map[string]interface{}{
				input2: input3,
			}
			s, err := structpb.NewStruct(m)
			if err != nil {
				return
			}
			input = structpb.NewStructValue(s)

		}

		expr, err := New()
		if err != nil {
			t.Fatal(err)
		}
		expr.Select(input, input4)
	})
}

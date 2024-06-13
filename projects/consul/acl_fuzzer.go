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

package acl

import (
	"strings"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
)

func FuzzNewPolicyFromSource(data []byte) int {
	defer func() {
		if r := recover(); r != nil {

			switch x := r.(type) {
			case error:
				// This panic represents a user error:
				if strings.Contains(x.Error(), "previous operation was not a successful ReadRune") {
					return
				}
			case string:

				// https://github.com/hashicorp/hcl/blob/1.0.x-vault/hcl/token/token.go#L162
				if strings.Contains(x, "err: invalid syntax") {
					return
				}
			}
			panic("fail")
		}
	}()
	f := fuzz.NewConsumer(data)
	rules, err := f.GetString()
	if err != nil {
		return 0
	}
	legacy, err := f.GetBool()
	if err != nil {
		return 0
	}
	if legacy {
		_, _ = NewPolicyFromSource(rules, SyntaxLegacy, nil, nil)
	} else {
		_, _ = NewPolicyFromSource(rules, SyntaxCurrent, nil, nil)
	}
	return 1
}

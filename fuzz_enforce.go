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

package casbin

func FuzzEnforce(data []byte) int {
	if len(data) < 4 {
		return 0
	}

	e, err := NewEnforcer()
	if err != nil {
		return 0
	}

	sub := string(data[:len(data)/3])
	obj := string(data[len(data)/3 : len(data)*2/3])
	act := string(data[len(data)*2/3:])

	_, _ = e.Enforce(sub, obj, act)
	return 1
}

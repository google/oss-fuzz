//  Copyright 2022 Google LLC
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

package toml

import (
	"bytes"
	"fmt"
)

func FuzzToml(data []byte) int {

	buf := make([]byte, 0, 2048)

	var v any
	_, err := Decode(string(data), &v)
	if err != nil {
		return 0
	}

	err = NewEncoder(bytes.NewBuffer(buf)).Encode(v)
	if err != nil {
		panic(fmt.Sprintf("failed to encode decoded document: %s", err))
	}

	var v2 any
	_, err = Decode(string(buf), &v2)
	if err != nil {
		panic(fmt.Sprintf("failed round trip: %s", err))
	}

	return 1
}

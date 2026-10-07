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

package readline

import (
	"testing"
)

func FuzzReadline(f *testing.F) {
	f.Fuzz(func(t *testing.T, line string) {
		rl, err := New(line)
		if err != nil {
			return
		}
		defer rl.Close()

		for {
			_, err := rl.Readline()
			if err != nil { // io.EOF
				break
			}
		}
	})
}

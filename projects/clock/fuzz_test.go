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

package clock

import (
	"testing"
	"time"
)

func FuzzClock(f *testing.F) {
	f.Fuzz(func(t *testing.T, addString, setString, timerString string) {
		addTime, err := time.ParseDuration(addString)
		if err != nil {
			return
		}
		setTime, err := time.Parse(time.RFC3339, setString)
		if err != nil {
			return
		}
		timerTime, err := time.ParseDuration(timerString)
		if err != nil {
			return
		}
		m := NewMock()
		m.Add(addTime)
		m.Set(setTime)
		m.Timer(timerTime)
	})
}

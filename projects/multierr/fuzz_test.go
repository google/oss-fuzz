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

package multierr

import (
	"errors"
	"testing"
)

func FuzzCombine(f *testing.F) {
	f.Fuzz(func(t *testing.T, err1, err2 string) {
		e1 := errors.New(err1)
		e2 := errors.New(err2)
		Combine(e1, e2)
	})
}


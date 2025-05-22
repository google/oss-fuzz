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

package schema

import (
	fuzz "github.com/AdaLogics/go-fuzz-headers"
)

func SchemaFuzzer(data []byte) int {
	pkgSpec := PackageSpec{}
	f := fuzz.NewConsumer(data)
	err := f.GenerateStruct(&pkgSpec)
	if err != nil {
		return 0
	}
	_, _ = ImportSpec(pkgSpec, nil)
	return 1
}

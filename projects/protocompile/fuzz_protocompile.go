// Copyright 2024 Google LLC
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

package protocompile

import (
	"bytes"
	"context"
	"io"
)

func FuzzProtoCompile(data []byte) int {
	compiler := &Compiler{
		Resolver: &SourceResolver{
			Accessor: func(_ string) (closer io.ReadCloser, e error) {
				return io.NopCloser(bytes.NewReader(data)), nil
			},
		},
	}

	_, err := compiler.Compile(context.Background(), "test.proto")
	if err != nil {
		return 0
	}
	return 1
}

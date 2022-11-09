// Copyright 2022 Google LLC. All Rights Reserved.
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

package tailfile

import (
	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"os"
)

func FuzzTailfile(data []byte) int {
	if len(data) < 5 {
		return 0
	}
	f := fuzz.NewConsumer(data)
	n, err := f.GetUint64()
	if err != nil {
		return 0
	}
	fileBytes, err := f.GetBytes()
	if err != nil {
		return 0
	}
	defer os.Remove("tailfile")
	fil, err := os.Create("tailfile")
	if err != nil {
		return 0
	}
	defer fil.Close()

	_, err = fil.Write(fileBytes)
	if err != nil {
		return 0
	}
	fil.Seek(0, 0)
	_, _ = TailFile(fil, int(n))
	return 1
}
